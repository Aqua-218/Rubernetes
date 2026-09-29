// Independent CSI plugin used as the M4 CSI oracle.
//
// It speaks the pinned CSI specification (v1.9.0) over gRPC on a Unix socket
// and produces real kernel effects: every volume is a directory under the
// state directory, NodeStageVolume bind-mounts it onto the staging path,
// NodePublishVolume bind-mounts the staging path onto the target (read-only
// when requested), and NodeGetVolumeStats answers from statfs(2).  Every RPC
// is journaled (request, response, gRPC status, and the plugin's own
// mountinfo readback) so the Ruby runner can compare what the production
// client believes happened with what the plugin actually did.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	csi "github.com/container-storage-interface/spec/lib/go/csi"
	protov1 "github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	pluginName    = "m4-oracle.csi.rubernetes.dev"
	vendorVersion = "csi-spec-1.9.0-oracle"
	nodeID        = "m4-oracle-node"
)

type volume struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Capacity  int64             `json:"capacityBytes"`
	Path      string            `json:"path"`
	Published map[string]bool   `json:"publishedNodes"`
	Staged    map[string]bool   `json:"stagedPaths"`
	Targets   map[string]bool   `json:"targets"`
	Params    map[string]string `json:"parameters"`
}

type snapshot struct {
	ID       string    `json:"id"`
	SourceID string    `json:"sourceVolumeId"`
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Created  time.Time `json:"createdAt"`
	Size     int64     `json:"sizeBytes"`
}

type mountReadback struct {
	Target     string `json:"target"`
	Mounted    bool   `json:"mounted"`
	MountID    string `json:"mountId,omitempty"`
	DeviceID   string `json:"deviceId,omitempty"`
	Root       string `json:"root,omitempty"`
	Filesystem string `json:"filesystem,omitempty"`
	Readonly   bool   `json:"readonly"`
	Line       string `json:"line,omitempty"`
}

type journalEntry struct {
	Sequence   int             `json:"sequence"`
	At         string          `json:"at"`
	Operation  string          `json:"operation"`
	Request    json.RawMessage `json:"request"`
	Response   json.RawMessage `json:"response,omitempty"`
	StatusCode string          `json:"status_code"`
	Error      string          `json:"error,omitempty"`
	Kernel     interface{}     `json:"kernel,omitempty"`
	VolumeID   string          `json:"volume_id,omitempty"`
}

type plugin struct {
	csi.UnimplementedIdentityServer
	csi.UnimplementedControllerServer
	csi.UnimplementedNodeServer

	mu        sync.Mutex
	stateDir  string
	journal   *os.File
	sequence  int
	volumes   map[string]*volume
	snapshots map[string]*snapshot
}

func newPlugin(stateDir, journalPath string) (*plugin, error) {
	if err := os.MkdirAll(filepath.Join(stateDir, "volumes"), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(stateDir, "snapshots"), 0o700); err != nil {
		return nil, err
	}
	journal, err := os.OpenFile(journalPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &plugin{stateDir: stateDir, journal: journal, volumes: map[string]*volume{}, snapshots: map[string]*snapshot{}}, nil
}

var jsonOptions = protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: false}

// The pinned CSI bindings are generated for the APIv1 protobuf runtime; they
// are wrapped for protojson so the journal carries every request/response
// field under its proto name.
func marshalMessage(message protov1.Message) json.RawMessage {
	if message == nil {
		return nil
	}
	raw, err := jsonOptions.Marshal(protov1.MessageV2(message))
	if err != nil {
		fallback, _ := json.Marshal(map[string]string{"marshal_error": err.Error()})
		return fallback
	}
	return raw
}

func (p *plugin) record(operation string, request protov1.Message, response protov1.Message, err error, kernel interface{}, volumeID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sequence++
	entry := journalEntry{Sequence: p.sequence, At: time.Now().UTC().Format(time.RFC3339Nano), Operation: operation, VolumeID: volumeID, Kernel: kernel}
	if request != nil && !isNilMessage(request) {
		entry.Request = marshalMessage(request)
	}
	if response != nil && !isNilMessage(response) {
		entry.Response = marshalMessage(response)
	}
	if err != nil {
		entry.Error = err.Error()
		entry.StatusCode = status.Code(err).String()
	} else {
		entry.StatusCode = codes.OK.String()
	}
	line, _ := json.Marshal(entry)
	p.journal.Write(append(line, '\n'))
	p.journal.Sync()
}

func isNilMessage(message protov1.Message) bool {
	if message == nil {
		return true
	}
	value := reflect.ValueOf(message)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

// ---------------------------------------------------------------- mounts --

func decodeMountinfoField(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}

func readMount(target string) mountReadback {
	target = filepath.Clean(target)
	result := mountReadback{Target: target}
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return result
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		fields := strings.Fields(parts[0])
		if len(fields) < 6 || decodeMountinfoField(fields[4]) != target {
			continue
		}
		after := strings.Fields(parts[1])
		options := strings.Split(fields[5], ",")
		readonly := false
		for _, option := range options {
			if option == "ro" {
				readonly = true
			}
		}
		result = mountReadback{Target: target, Mounted: true, MountID: fields[0], DeviceID: fields[2], Root: decodeMountinfoField(fields[3]), Readonly: readonly, Line: line}
		if len(after) > 0 {
			result.Filesystem = after[0]
		}
	}
	return result
}

func bindMount(source, target string, readonly bool) error {
	if err := os.MkdirAll(target, 0o750); err != nil {
		return err
	}
	if err := syscall.Mount(source, target, "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("mount(2) bind %s -> %s: %w", source, target, err)
	}
	if readonly {
		if err := syscall.Mount("", target, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
			_ = syscall.Unmount(target, 0)
			return fmt.Errorf("mount(2) read-only remount %s: %w", target, err)
		}
	}
	return nil
}

func unmount(target string) error {
	if !readMount(target).Mounted {
		return nil
	}
	if err := syscall.Unmount(target, 0); err != nil {
		return fmt.Errorf("umount2(2) %s: %w", target, err)
	}
	if readMount(target).Mounted {
		return fmt.Errorf("umount2(2) %s reported success but the mount remains", target)
	}
	return nil
}

// -------------------------------------------------------------- identity --

func (p *plugin) GetPluginInfo(ctx context.Context, req *csi.GetPluginInfoRequest) (*csi.GetPluginInfoResponse, error) {
	resp := &csi.GetPluginInfoResponse{Name: pluginName, VendorVersion: vendorVersion}
	p.record("GetPluginInfo", req, resp, nil, nil, "")
	return resp, nil
}

func (p *plugin) GetPluginCapabilities(ctx context.Context, req *csi.GetPluginCapabilitiesRequest) (*csi.GetPluginCapabilitiesResponse, error) {
	resp := &csi.GetPluginCapabilitiesResponse{Capabilities: []*csi.PluginCapability{
		{Type: &csi.PluginCapability_Service_{Service: &csi.PluginCapability_Service{Type: csi.PluginCapability_Service_CONTROLLER_SERVICE}}},
		{Type: &csi.PluginCapability_VolumeExpansion_{VolumeExpansion: &csi.PluginCapability_VolumeExpansion{Type: csi.PluginCapability_VolumeExpansion_ONLINE}}},
	}}
	p.record("GetPluginCapabilities", req, resp, nil, nil, "")
	return resp, nil
}

func (p *plugin) Probe(ctx context.Context, req *csi.ProbeRequest) (*csi.ProbeResponse, error) {
	resp := &csi.ProbeResponse{}
	p.record("Probe", req, resp, nil, nil, "")
	return resp, nil
}

// ------------------------------------------------------------ controller --

func volumeIDFor(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "m4csi-" + hex.EncodeToString(sum[:])[:16]
}

func (p *plugin) CreateVolume(ctx context.Context, req *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error) {
	var resp *csi.CreateVolumeResponse
	var err error
	func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if req.GetName() == "" {
			err = status.Error(codes.InvalidArgument, "name is required")
			return
		}
		if len(req.GetVolumeCapabilities()) == 0 {
			err = status.Error(codes.InvalidArgument, "volume capabilities are required")
			return
		}
		capacity := req.GetCapacityRange().GetRequiredBytes()
		if capacity <= 0 {
			capacity = 1 << 20
		}
		id := volumeIDFor(req.GetName())
		if existing, ok := p.volumes[id]; ok {
			if existing.Capacity != capacity {
				err = status.Error(codes.AlreadyExists, "volume exists with a different capacity")
				return
			}
			resp = &csi.CreateVolumeResponse{Volume: &csi.Volume{VolumeId: existing.ID, CapacityBytes: existing.Capacity, VolumeContext: map[string]string{"m4-oracle/path": existing.Path}}}
			return
		}
		path := filepath.Join(p.stateDir, "volumes", id)
		if mkErr := os.MkdirAll(path, 0o750); mkErr != nil {
			err = status.Errorf(codes.Internal, "create volume directory: %v", mkErr)
			return
		}
		if source := req.GetVolumeContentSource(); source != nil {
			if snap := source.GetSnapshot(); snap != nil {
				record, ok := p.snapshots[snap.GetSnapshotId()]
				if !ok {
					_ = os.RemoveAll(path)
					err = status.Error(codes.NotFound, "snapshot does not exist")
					return
				}
				if copyErr := copyTree(record.Path, path); copyErr != nil {
					_ = os.RemoveAll(path)
					err = status.Errorf(codes.Internal, "restore snapshot: %v", copyErr)
					return
				}
			}
		}
		p.volumes[id] = &volume{ID: id, Name: req.GetName(), Capacity: capacity, Path: path, Published: map[string]bool{}, Staged: map[string]bool{}, Targets: map[string]bool{}, Params: req.GetParameters()}
		resp = &csi.CreateVolumeResponse{Volume: &csi.Volume{VolumeId: id, CapacityBytes: capacity, VolumeContext: map[string]string{"m4-oracle/path": path}, ContentSource: req.GetVolumeContentSource()}}
	}()
	p.record("CreateVolume", req, resp, err, nil, req.GetName())
	return resp, err
}

func copyTree(source, destination string) error {
	return filepath.Walk(source, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
}

func (p *plugin) DeleteVolume(ctx context.Context, req *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error) {
	var err error
	func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if req.GetVolumeId() == "" {
			err = status.Error(codes.InvalidArgument, "volume id is required")
			return
		}
		record, ok := p.volumes[req.GetVolumeId()]
		if !ok {
			return
		}
		if len(record.Published) > 0 || len(record.Staged) > 0 || len(record.Targets) > 0 {
			err = status.Error(codes.FailedPrecondition, "volume is still published or staged")
			return
		}
		if rmErr := os.RemoveAll(record.Path); rmErr != nil {
			err = status.Errorf(codes.Internal, "remove volume directory: %v", rmErr)
			return
		}
		delete(p.volumes, req.GetVolumeId())
	}()
	resp := &csi.DeleteVolumeResponse{}
	if err != nil {
		resp = nil
	}
	p.record("DeleteVolume", req, resp, err, nil, req.GetVolumeId())
	return resp, err
}

func (p *plugin) ControllerPublishVolume(ctx context.Context, req *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error) {
	var resp *csi.ControllerPublishVolumeResponse
	var err error
	func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		record, ok := p.volumes[req.GetVolumeId()]
		if !ok {
			err = status.Error(codes.NotFound, "volume does not exist")
			return
		}
		if req.GetNodeId() == "" {
			err = status.Error(codes.InvalidArgument, "node id is required")
			return
		}
		if req.GetVolumeCapability() == nil {
			err = status.Error(codes.InvalidArgument, "volume capability is required")
			return
		}
		mode := req.GetVolumeCapability().GetAccessMode().GetMode()
		singleNode := mode == csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER || mode == csi.VolumeCapability_AccessMode_SINGLE_NODE_SINGLE_WRITER || mode == csi.VolumeCapability_AccessMode_SINGLE_NODE_MULTI_WRITER
		for node := range record.Published {
			if node != req.GetNodeId() && singleNode {
				err = status.Errorf(codes.FailedPrecondition, "volume is already published to node %s", node)
				return
			}
		}
		record.Published[req.GetNodeId()] = true
		resp = &csi.ControllerPublishVolumeResponse{PublishContext: map[string]string{"m4-oracle/node": req.GetNodeId(), "m4-oracle/path": record.Path}}
	}()
	p.record("ControllerPublishVolume", req, resp, err, nil, req.GetVolumeId())
	return resp, err
}

func (p *plugin) ControllerUnpublishVolume(ctx context.Context, req *csi.ControllerUnpublishVolumeRequest) (*csi.ControllerUnpublishVolumeResponse, error) {
	var err error
	func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		record, ok := p.volumes[req.GetVolumeId()]
		if !ok {
			return
		}
		if req.GetNodeId() == "" {
			for node := range record.Published {
				delete(record.Published, node)
			}
			return
		}
		delete(record.Published, req.GetNodeId())
	}()
	resp := &csi.ControllerUnpublishVolumeResponse{}
	if err != nil {
		resp = nil
	}
	p.record("ControllerUnpublishVolume", req, resp, err, nil, req.GetVolumeId())
	return resp, err
}

func (p *plugin) ValidateVolumeCapabilities(ctx context.Context, req *csi.ValidateVolumeCapabilitiesRequest) (*csi.ValidateVolumeCapabilitiesResponse, error) {
	p.mu.Lock()
	_, ok := p.volumes[req.GetVolumeId()]
	p.mu.Unlock()
	var resp *csi.ValidateVolumeCapabilitiesResponse
	var err error
	if !ok {
		err = status.Error(codes.NotFound, "volume does not exist")
	} else {
		resp = &csi.ValidateVolumeCapabilitiesResponse{Confirmed: &csi.ValidateVolumeCapabilitiesResponse_Confirmed{VolumeCapabilities: req.GetVolumeCapabilities(), VolumeContext: req.GetVolumeContext(), Parameters: req.GetParameters()}}
	}
	p.record("ValidateVolumeCapabilities", req, resp, err, nil, req.GetVolumeId())
	return resp, err
}

func (p *plugin) ListVolumes(ctx context.Context, req *csi.ListVolumesRequest) (*csi.ListVolumesResponse, error) {
	p.mu.Lock()
	entries := []*csi.ListVolumesResponse_Entry{}
	for _, record := range p.volumes {
		nodes := []string{}
		for node := range record.Published {
			nodes = append(nodes, node)
		}
		entries = append(entries, &csi.ListVolumesResponse_Entry{Volume: &csi.Volume{VolumeId: record.ID, CapacityBytes: record.Capacity}, Status: &csi.ListVolumesResponse_VolumeStatus{PublishedNodeIds: nodes}})
	}
	p.mu.Unlock()
	resp := &csi.ListVolumesResponse{Entries: entries}
	p.record("ListVolumes", req, resp, nil, nil, "")
	return resp, nil
}

func (p *plugin) GetCapacity(ctx context.Context, req *csi.GetCapacityRequest) (*csi.GetCapacityResponse, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(p.stateDir, &stat); err != nil {
		return nil, status.Errorf(codes.Internal, "statfs: %v", err)
	}
	resp := &csi.GetCapacityResponse{AvailableCapacity: int64(stat.Bavail) * int64(stat.Bsize)}
	p.record("GetCapacity", req, resp, nil, nil, "")
	return resp, nil
}

func (p *plugin) ControllerGetCapabilities(ctx context.Context, req *csi.ControllerGetCapabilitiesRequest) (*csi.ControllerGetCapabilitiesResponse, error) {
	kinds := []csi.ControllerServiceCapability_RPC_Type{
		csi.ControllerServiceCapability_RPC_CREATE_DELETE_VOLUME,
		csi.ControllerServiceCapability_RPC_PUBLISH_UNPUBLISH_VOLUME,
		csi.ControllerServiceCapability_RPC_LIST_VOLUMES,
		csi.ControllerServiceCapability_RPC_GET_CAPACITY,
		csi.ControllerServiceCapability_RPC_CREATE_DELETE_SNAPSHOT,
		csi.ControllerServiceCapability_RPC_LIST_SNAPSHOTS,
		csi.ControllerServiceCapability_RPC_EXPAND_VOLUME,
		csi.ControllerServiceCapability_RPC_LIST_VOLUMES_PUBLISHED_NODES,
	}
	capabilities := []*csi.ControllerServiceCapability{}
	for _, kind := range kinds {
		capabilities = append(capabilities, &csi.ControllerServiceCapability{Type: &csi.ControllerServiceCapability_Rpc{Rpc: &csi.ControllerServiceCapability_RPC{Type: kind}}})
	}
	resp := &csi.ControllerGetCapabilitiesResponse{Capabilities: capabilities}
	p.record("ControllerGetCapabilities", req, resp, nil, nil, "")
	return resp, nil
}

func (p *plugin) CreateSnapshot(ctx context.Context, req *csi.CreateSnapshotRequest) (*csi.CreateSnapshotResponse, error) {
	var resp *csi.CreateSnapshotResponse
	var err error
	func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		record, ok := p.volumes[req.GetSourceVolumeId()]
		if !ok {
			err = status.Error(codes.NotFound, "source volume does not exist")
			return
		}
		if req.GetName() == "" {
			err = status.Error(codes.InvalidArgument, "name is required")
			return
		}
		id := "m4snap-" + volumeIDFor(req.GetName())[6:]
		if existing, ok := p.snapshots[id]; ok {
			if existing.SourceID != record.ID {
				err = status.Error(codes.AlreadyExists, "snapshot exists for a different source volume")
				return
			}
			resp = &csi.CreateSnapshotResponse{Snapshot: snapshotMessage(existing)}
			return
		}
		path := filepath.Join(p.stateDir, "snapshots", id)
		if copyErr := copyTree(record.Path, path); copyErr != nil {
			_ = os.RemoveAll(path)
			err = status.Errorf(codes.Internal, "copy snapshot: %v", copyErr)
			return
		}
		size := int64(0)
		_ = filepath.Walk(path, func(_ string, info os.FileInfo, walkErr error) error {
			if walkErr == nil && info.Mode().IsRegular() {
				size += info.Size()
			}
			return nil
		})
		snap := &snapshot{ID: id, SourceID: record.ID, Name: req.GetName(), Path: path, Created: time.Now().UTC(), Size: size}
		p.snapshots[id] = snap
		resp = &csi.CreateSnapshotResponse{Snapshot: snapshotMessage(snap)}
	}()
	p.record("CreateSnapshot", req, resp, err, nil, req.GetSourceVolumeId())
	return resp, err
}

func snapshotMessage(snap *snapshot) *csi.Snapshot {
	return &csi.Snapshot{SnapshotId: snap.ID, SourceVolumeId: snap.SourceID, SizeBytes: snap.Size, ReadyToUse: true, CreationTime: timestampOf(snap.Created)}
}

func (p *plugin) DeleteSnapshot(ctx context.Context, req *csi.DeleteSnapshotRequest) (*csi.DeleteSnapshotResponse, error) {
	p.mu.Lock()
	if snap, ok := p.snapshots[req.GetSnapshotId()]; ok {
		_ = os.RemoveAll(snap.Path)
		delete(p.snapshots, req.GetSnapshotId())
	}
	p.mu.Unlock()
	resp := &csi.DeleteSnapshotResponse{}
	p.record("DeleteSnapshot", req, resp, nil, nil, "")
	return resp, nil
}

func (p *plugin) ListSnapshots(ctx context.Context, req *csi.ListSnapshotsRequest) (*csi.ListSnapshotsResponse, error) {
	p.mu.Lock()
	entries := []*csi.ListSnapshotsResponse_Entry{}
	for _, snap := range p.snapshots {
		if req.GetSnapshotId() != "" && req.GetSnapshotId() != snap.ID {
			continue
		}
		if req.GetSourceVolumeId() != "" && req.GetSourceVolumeId() != snap.SourceID {
			continue
		}
		entries = append(entries, &csi.ListSnapshotsResponse_Entry{Snapshot: snapshotMessage(snap)})
	}
	p.mu.Unlock()
	resp := &csi.ListSnapshotsResponse{Entries: entries}
	p.record("ListSnapshots", req, resp, nil, nil, "")
	return resp, nil
}

func (p *plugin) ControllerExpandVolume(ctx context.Context, req *csi.ControllerExpandVolumeRequest) (*csi.ControllerExpandVolumeResponse, error) {
	var resp *csi.ControllerExpandVolumeResponse
	var err error
	func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		record, ok := p.volumes[req.GetVolumeId()]
		if !ok {
			err = status.Error(codes.NotFound, "volume does not exist")
			return
		}
		required := req.GetCapacityRange().GetRequiredBytes()
		if required > record.Capacity {
			record.Capacity = required
		}
		resp = &csi.ControllerExpandVolumeResponse{CapacityBytes: record.Capacity, NodeExpansionRequired: true}
	}()
	p.record("ControllerExpandVolume", req, resp, err, nil, req.GetVolumeId())
	return resp, err
}

// ------------------------------------------------------------------ node --

func (p *plugin) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	var resp *csi.NodeStageVolumeResponse
	var err error
	var kernel interface{}
	func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		record, ok := p.volumes[req.GetVolumeId()]
		if !ok {
			err = status.Error(codes.NotFound, "volume does not exist")
			return
		}
		if req.GetStagingTargetPath() == "" {
			err = status.Error(codes.InvalidArgument, "staging target path is required")
			return
		}
		if req.GetVolumeCapability() == nil {
			err = status.Error(codes.InvalidArgument, "volume capability is required")
			return
		}
		target := filepath.Clean(req.GetStagingTargetPath())
		if existing := readMount(target); existing.Mounted {
			kernel = existing
			record.Staged[target] = true
			resp = &csi.NodeStageVolumeResponse{}
			return
		}
		readonly := req.GetVolumeCapability().GetAccessMode().GetMode() == csi.VolumeCapability_AccessMode_MULTI_NODE_READER_ONLY || req.GetVolumeCapability().GetAccessMode().GetMode() == csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY
		if mountErr := bindMount(record.Path, target, readonly); mountErr != nil {
			err = status.Errorf(codes.Internal, "%v", mountErr)
			return
		}
		record.Staged[target] = true
		kernel = readMount(target)
		resp = &csi.NodeStageVolumeResponse{}
	}()
	p.record("NodeStageVolume", req, resp, err, kernel, req.GetVolumeId())
	return resp, err
}

func (p *plugin) NodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	var resp *csi.NodeUnstageVolumeResponse
	var err error
	var kernel interface{}
	func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if req.GetStagingTargetPath() == "" {
			err = status.Error(codes.InvalidArgument, "staging target path is required")
			return
		}
		target := filepath.Clean(req.GetStagingTargetPath())
		if unmountErr := unmount(target); unmountErr != nil {
			err = status.Errorf(codes.Internal, "%v", unmountErr)
			return
		}
		if record, ok := p.volumes[req.GetVolumeId()]; ok {
			delete(record.Staged, target)
		}
		kernel = readMount(target)
		resp = &csi.NodeUnstageVolumeResponse{}
	}()
	p.record("NodeUnstageVolume", req, resp, err, kernel, req.GetVolumeId())
	return resp, err
}

func (p *plugin) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	var resp *csi.NodePublishVolumeResponse
	var err error
	var kernel interface{}
	func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		record, ok := p.volumes[req.GetVolumeId()]
		if !ok {
			err = status.Error(codes.NotFound, "volume does not exist")
			return
		}
		if req.GetTargetPath() == "" {
			err = status.Error(codes.InvalidArgument, "target path is required")
			return
		}
		if req.GetVolumeCapability() == nil {
			err = status.Error(codes.InvalidArgument, "volume capability is required")
			return
		}
		source := filepath.Clean(req.GetStagingTargetPath())
		if source == "" || source == "." || !readMount(source).Mounted {
			err = status.Error(codes.FailedPrecondition, "volume is not staged at the staging target path")
			return
		}
		target := filepath.Clean(req.GetTargetPath())
		if existing := readMount(target); existing.Mounted {
			kernel = existing
			record.Targets[target] = true
			resp = &csi.NodePublishVolumeResponse{}
			return
		}
		if mountErr := bindMount(source, target, req.GetReadonly()); mountErr != nil {
			err = status.Errorf(codes.Internal, "%v", mountErr)
			return
		}
		record.Targets[target] = true
		kernel = readMount(target)
		resp = &csi.NodePublishVolumeResponse{}
	}()
	p.record("NodePublishVolume", req, resp, err, kernel, req.GetVolumeId())
	return resp, err
}

func (p *plugin) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	var resp *csi.NodeUnpublishVolumeResponse
	var err error
	var kernel interface{}
	func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if req.GetTargetPath() == "" {
			err = status.Error(codes.InvalidArgument, "target path is required")
			return
		}
		target := filepath.Clean(req.GetTargetPath())
		if unmountErr := unmount(target); unmountErr != nil {
			err = status.Errorf(codes.Internal, "%v", unmountErr)
			return
		}
		if record, ok := p.volumes[req.GetVolumeId()]; ok {
			delete(record.Targets, target)
		}
		kernel = readMount(target)
		resp = &csi.NodeUnpublishVolumeResponse{}
	}()
	p.record("NodeUnpublishVolume", req, resp, err, kernel, req.GetVolumeId())
	return resp, err
}

func (p *plugin) NodeGetVolumeStats(ctx context.Context, req *csi.NodeGetVolumeStatsRequest) (*csi.NodeGetVolumeStatsResponse, error) {
	var resp *csi.NodeGetVolumeStatsResponse
	var err error
	var kernel interface{}
	if req.GetVolumePath() == "" {
		err = status.Error(codes.InvalidArgument, "volume path is required")
	} else if mount := readMount(filepath.Clean(req.GetVolumePath())); !mount.Mounted {
		err = status.Error(codes.NotFound, "volume path is not mounted")
	} else {
		var stat syscall.Statfs_t
		if statErr := syscall.Statfs(req.GetVolumePath(), &stat); statErr != nil {
			err = status.Errorf(codes.Internal, "statfs: %v", statErr)
		} else {
			total := int64(stat.Blocks) * int64(stat.Bsize)
			available := int64(stat.Bavail) * int64(stat.Bsize)
			used := total - int64(stat.Bfree)*int64(stat.Bsize)
			resp = &csi.NodeGetVolumeStatsResponse{Usage: []*csi.VolumeUsage{
				{Unit: csi.VolumeUsage_BYTES, Total: total, Available: available, Used: used},
				{Unit: csi.VolumeUsage_INODES, Total: int64(stat.Files), Available: int64(stat.Ffree), Used: int64(stat.Files) - int64(stat.Ffree)},
			}, VolumeCondition: &csi.VolumeCondition{Abnormal: false, Message: "mounted"}}
			kernel = map[string]interface{}{"mount": mount, "total_bytes": total, "available_bytes": available, "filesystem_type": fmt.Sprintf("0x%x", stat.Type)}
		}
	}
	p.record("NodeGetVolumeStats", req, resp, err, kernel, req.GetVolumeId())
	return resp, err
}

func (p *plugin) NodeExpandVolume(ctx context.Context, req *csi.NodeExpandVolumeRequest) (*csi.NodeExpandVolumeResponse, error) {
	resp := &csi.NodeExpandVolumeResponse{CapacityBytes: req.GetCapacityRange().GetRequiredBytes()}
	p.record("NodeExpandVolume", req, resp, nil, nil, req.GetVolumeId())
	return resp, nil
}

func (p *plugin) NodeGetCapabilities(ctx context.Context, req *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	kinds := []csi.NodeServiceCapability_RPC_Type{
		csi.NodeServiceCapability_RPC_STAGE_UNSTAGE_VOLUME,
		csi.NodeServiceCapability_RPC_GET_VOLUME_STATS,
		csi.NodeServiceCapability_RPC_EXPAND_VOLUME,
		csi.NodeServiceCapability_RPC_VOLUME_CONDITION,
	}
	capabilities := []*csi.NodeServiceCapability{}
	for _, kind := range kinds {
		capabilities = append(capabilities, &csi.NodeServiceCapability{Type: &csi.NodeServiceCapability_Rpc{Rpc: &csi.NodeServiceCapability_RPC{Type: kind}}})
	}
	resp := &csi.NodeGetCapabilitiesResponse{Capabilities: capabilities}
	p.record("NodeGetCapabilities", req, resp, nil, nil, "")
	return resp, nil
}

func (p *plugin) NodeGetInfo(ctx context.Context, req *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	resp := &csi.NodeGetInfoResponse{NodeId: nodeID, MaxVolumesPerNode: 64}
	p.record("NodeGetInfo", req, resp, nil, nil, "")
	return resp, nil
}

// ------------------------------------------------------------------ main --

func main() {
	endpoint := flag.String("endpoint", "", "unix socket path")
	stateDir := flag.String("state-dir", "", "directory for volumes and snapshots")
	journalPath := flag.String("journal", "", "JSON-lines journal path")
	flag.Parse()
	if *endpoint == "" || *stateDir == "" || *journalPath == "" {
		fmt.Fprintln(os.Stderr, "usage: plugin --endpoint PATH --state-dir DIR --journal PATH")
		os.Exit(2)
	}
	p, err := newPlugin(*stateDir, *journalPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = os.Remove(*endpoint)
	listener, err := net.Listen("unix", *endpoint)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.Chmod(*endpoint, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	server := grpc.NewServer()
	csi.RegisterIdentityServer(server, p)
	csi.RegisterControllerServer(server, p)
	csi.RegisterNodeServer(server, p)
	ready, _ := json.Marshal(map[string]interface{}{"ready": true, "pid": os.Getpid(), "endpoint": *endpoint, "plugin": pluginName, "vendor_version": vendorVersion})
	fmt.Println(string(ready))
	if err := server.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
