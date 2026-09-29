# frozen_string_literal: true

# Server-side apply and managedFields tracking: a port of
# sigs.k8s.io/structured-merge-diff/v6 and
# k8s.io/apimachinery/pkg/util/managedfields (Kubernetes v1.36.2).
require_relative "managed_fields/value"
require_relative "managed_fields/fieldpath"
require_relative "managed_fields/schema"
require_relative "managed_fields/typed"
require_relative "managed_fields/updater"
require_relative "managed_fields/field_manager"
