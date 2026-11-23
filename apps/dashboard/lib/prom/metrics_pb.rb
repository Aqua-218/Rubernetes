# frozen_string_literal: true

# Generated from vendor/prometheus/metrics.proto (Prometheus client_model v0.6.2).
require "google/protobuf"
require "google/protobuf/descriptor_pb"
require "google/protobuf/timestamp_pb"

module Prom
  module MetricsPb
    pool = Google::Protobuf::DescriptorPool.new
    timestamp = Google::Protobuf::DescriptorPool.generated_pool.lookup("google.protobuf.Timestamp")
    pool.add_serialized_file(timestamp.file_descriptor.to_proto.to_proto)
    descriptor = <<~BASE64.unpack1("m")
      Cg1tZXRyaWNzLnByb3RvEhRpby5wcm9tZXRoZXVzLmNsaWVudBofZ29vZ2xl
      L3Byb3RvYnVmL3RpbWVzdGFtcC5wcm90byI1CglMYWJlbFBhaXISEgoEbmFt
      ZRgBIAEoCVIEbmFtZRIUCgV2YWx1ZRgCIAEoCVIFdmFsdWUiHQoFR2F1Z2US
      FAoFdmFsdWUYASABKAFSBXZhbHVlIqQBCgdDb3VudGVyEhQKBXZhbHVlGAEg
      ASgBUgV2YWx1ZRI6CghleGVtcGxhchgCIAEoCzIeLmlvLnByb21ldGhldXMu
      Y2xpZW50LkV4ZW1wbGFyUghleGVtcGxhchJHChFjcmVhdGVkX3RpbWVzdGFt
      cBgDIAEoCzIaLmdvb2dsZS5wcm90b2J1Zi5UaW1lc3RhbXBSEGNyZWF0ZWRU
      aW1lc3RhbXAiPAoIUXVhbnRpbGUSGgoIcXVhbnRpbGUYASABKAFSCHF1YW50
      aWxlEhQKBXZhbHVlGAIgASgBUgV2YWx1ZSLQAQoHU3VtbWFyeRIhCgxzYW1w
      bGVfY291bnQYASABKARSC3NhbXBsZUNvdW50Eh0KCnNhbXBsZV9zdW0YAiAB
      KAFSCXNhbXBsZVN1bRI6CghxdWFudGlsZRgDIAMoCzIeLmlvLnByb21ldGhl
      dXMuY2xpZW50LlF1YW50aWxlUghxdWFudGlsZRJHChFjcmVhdGVkX3RpbWVz
      dGFtcBgEIAEoCzIaLmdvb2dsZS5wcm90b2J1Zi5UaW1lc3RhbXBSEGNyZWF0
      ZWRUaW1lc3RhbXAiHwoHVW50eXBlZBIUCgV2YWx1ZRgBIAEoAVIFdmFsdWUi
      6gUKCUhpc3RvZ3JhbRIhCgxzYW1wbGVfY291bnQYASABKARSC3NhbXBsZUNv
      dW50EiwKEnNhbXBsZV9jb3VudF9mbG9hdBgEIAEoAVIQc2FtcGxlQ291bnRG
      bG9hdBIdCgpzYW1wbGVfc3VtGAIgASgBUglzYW1wbGVTdW0SNAoGYnVja2V0
      GAMgAygLMhwuaW8ucHJvbWV0aGV1cy5jbGllbnQuQnVja2V0UgZidWNrZXQS
      RwoRY3JlYXRlZF90aW1lc3RhbXAYDyABKAsyGi5nb29nbGUucHJvdG9idWYu
      VGltZXN0YW1wUhBjcmVhdGVkVGltZXN0YW1wEhYKBnNjaGVtYRgFIAEoEVIG
      c2NoZW1hEiUKDnplcm9fdGhyZXNob2xkGAYgASgBUg16ZXJvVGhyZXNob2xk
      Eh0KCnplcm9fY291bnQYByABKARSCXplcm9Db3VudBIoChB6ZXJvX2NvdW50
      X2Zsb2F0GAggASgBUg56ZXJvQ291bnRGbG9hdBJFCg1uZWdhdGl2ZV9zcGFu
      GAkgAygLMiAuaW8ucHJvbWV0aGV1cy5jbGllbnQuQnVja2V0U3BhblIMbmVn
      YXRpdmVTcGFuEiUKDm5lZ2F0aXZlX2RlbHRhGAogAygSUg1uZWdhdGl2ZURl
      bHRhEiUKDm5lZ2F0aXZlX2NvdW50GAsgAygBUg1uZWdhdGl2ZUNvdW50EkUK
      DXBvc2l0aXZlX3NwYW4YDCADKAsyIC5pby5wcm9tZXRoZXVzLmNsaWVudC5C
      dWNrZXRTcGFuUgxwb3NpdGl2ZVNwYW4SJQoOcG9zaXRpdmVfZGVsdGEYDSAD
      KBJSDXBvc2l0aXZlRGVsdGESJQoOcG9zaXRpdmVfY291bnQYDiADKAFSDXBv
      c2l0aXZlQ291bnQSPAoJZXhlbXBsYXJzGBAgAygLMh4uaW8ucHJvbWV0aGV1
      cy5jbGllbnQuRXhlbXBsYXJSCWV4ZW1wbGFycyLGAQoGQnVja2V0EikKEGN1
      bXVsYXRpdmVfY291bnQYASABKARSD2N1bXVsYXRpdmVDb3VudBI0ChZjdW11
      bGF0aXZlX2NvdW50X2Zsb2F0GAQgASgBUhRjdW11bGF0aXZlQ291bnRGbG9h
      dBIfCgt1cHBlcl9ib3VuZBgCIAEoAVIKdXBwZXJCb3VuZBI6CghleGVtcGxh
      chgDIAEoCzIeLmlvLnByb21ldGhldXMuY2xpZW50LkV4ZW1wbGFyUghleGVt
      cGxhciI8CgpCdWNrZXRTcGFuEhYKBm9mZnNldBgBIAEoEVIGb2Zmc2V0EhYK
      Bmxlbmd0aBgCIAEoDVIGbGVuZ3RoIpEBCghFeGVtcGxhchI1CgVsYWJlbBgB
      IAMoCzIfLmlvLnByb21ldGhldXMuY2xpZW50LkxhYmVsUGFpclIFbGFiZWwS
      FAoFdmFsdWUYAiABKAFSBXZhbHVlEjgKCXRpbWVzdGFtcBgDIAEoCzIaLmdv
      b2dsZS5wcm90b2J1Zi5UaW1lc3RhbXBSCXRpbWVzdGFtcCL/AgoGTWV0cmlj
      EjUKBWxhYmVsGAEgAygLMh8uaW8ucHJvbWV0aGV1cy5jbGllbnQuTGFiZWxQ
      YWlyUgVsYWJlbBIxCgVnYXVnZRgCIAEoCzIbLmlvLnByb21ldGhldXMuY2xp
      ZW50LkdhdWdlUgVnYXVnZRI3Cgdjb3VudGVyGAMgASgLMh0uaW8ucHJvbWV0
      aGV1cy5jbGllbnQuQ291bnRlclIHY291bnRlchI3CgdzdW1tYXJ5GAQgASgL
      Mh0uaW8ucHJvbWV0aGV1cy5jbGllbnQuU3VtbWFyeVIHc3VtbWFyeRI3Cgd1
      bnR5cGVkGAUgASgLMh0uaW8ucHJvbWV0aGV1cy5jbGllbnQuVW50eXBlZFIH
      dW50eXBlZBI9CgloaXN0b2dyYW0YByABKAsyHy5pby5wcm9tZXRoZXVzLmNs
      aWVudC5IaXN0b2dyYW1SCWhpc3RvZ3JhbRIhCgx0aW1lc3RhbXBfbXMYBiAB
      KANSC3RpbWVzdGFtcE1zIrYBCgxNZXRyaWNGYW1pbHkSEgoEbmFtZRgBIAEo
      CVIEbmFtZRISCgRoZWxwGAIgASgJUgRoZWxwEjQKBHR5cGUYAyABKA4yIC5p
      by5wcm9tZXRoZXVzLmNsaWVudC5NZXRyaWNUeXBlUgR0eXBlEjQKBm1ldHJp
      YxgEIAMoCzIcLmlvLnByb21ldGhldXMuY2xpZW50Lk1ldHJpY1IGbWV0cmlj
      EhIKBHVuaXQYBSABKAlSBHVuaXQqYgoKTWV0cmljVHlwZRILCgdDT1VOVEVS
      EAASCQoFR0FVR0UQARILCgdTVU1NQVJZEAISCwoHVU5UWVBFRBADEg0KCUhJ
      U1RPR1JBTRAEEhMKD0dBVUdFX0hJU1RPR1JBTRAFQmQKFGlvLnByb21ldGhl
      dXMuY2xpZW50WjpnaXRodWIuY29tL3Byb21ldGhldXMvY2xpZW50X21vZGVs
      L2dvO2lvX3Byb21ldGhldXNfY2xpZW506gIPUHJvbTo6TWV0cmljc1Bi
    BASE64
    pool.add_serialized_file(descriptor)

    LabelPair = pool.lookup("io.prometheus.client.LabelPair").msgclass
    Gauge = pool.lookup("io.prometheus.client.Gauge").msgclass
    Counter = pool.lookup("io.prometheus.client.Counter").msgclass
    Quantile = pool.lookup("io.prometheus.client.Quantile").msgclass
    Summary = pool.lookup("io.prometheus.client.Summary").msgclass
    Untyped = pool.lookup("io.prometheus.client.Untyped").msgclass
    Histogram = pool.lookup("io.prometheus.client.Histogram").msgclass
    Bucket = pool.lookup("io.prometheus.client.Bucket").msgclass
    BucketSpan = pool.lookup("io.prometheus.client.BucketSpan").msgclass
    Exemplar = pool.lookup("io.prometheus.client.Exemplar").msgclass
    Metric = pool.lookup("io.prometheus.client.Metric").msgclass
    MetricFamily = pool.lookup("io.prometheus.client.MetricFamily").msgclass
  end
end
