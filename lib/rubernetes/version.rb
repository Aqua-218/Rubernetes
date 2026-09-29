# frozen_string_literal: true

module Rubernetes
  VERSION = "0.1.0"
  # The Kubernetes release the components stand in for: what kubelet reports
  # as status.nodeInfo.kubeletVersion (version.Get().String()) and client-go
  # puts in its user agent.
  KUBERNETES_GIT_VERSION = "v1.36.2"

  GO_ARCH = {"x86_64" => "amd64", "amd64" => "amd64", "aarch64" => "arm64", "arm64" => "arm64", "i686" => "386",
             "i386" => "386", "armv7l" => "arm", "s390x" => "s390x", "ppc64le" => "ppc64le"}.freeze

  # runtime.GOOS + "/" + runtime.GOARCH, as version.Get().Platform reports it.
  def self.go_platform
    require "rbconfig"
    os = RbConfig::CONFIG["host_os"].to_s[/\A[a-z]+/].to_s
    os = "linux" if os.empty?
    cpu = RbConfig::CONFIG["host_cpu"].to_s
    "#{os}/#{GO_ARCH.fetch(cpu, cpu)}"
  end
end
