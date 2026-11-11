# frozen_string_literal: true

require_relative "extension/definition"
require_relative "extension/resource"

module Rubernetes
  # Cluster behaviour written as a Ruby file and loaded into the running
  # components: scheduler plugins, admission hooks and controllers.
  #
  # Upstream needs a rebuilt kube-scheduler for a scheduler plugin, a webhook
  # server with its own TLS for an admission hook, and a separately deployed
  # operator for a controller.  Here all three are blocks in one file, stored
  # in the API as an Extension object (rubernetes.io/v1alpha1) and evaluated
  # inside the scheduler, the API servers and the controller manager -- which
  # is why creating one takes cluster-admin, and why every component loads
  # them only when its configuration says `extensions: {enabled: true}`.
  module Extension
  end
end
