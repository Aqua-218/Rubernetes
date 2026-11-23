# frozen_string_literal: true

module Rubernetes
  # Kubernetes core/v1 Signal names and the corresponding CRI enum spellings.
  module ContainerStopSignals
    GATE = "ContainerStopSignals"
    CONTAINER_FIELDS = %w[containers initContainers ephemeralContainers].freeze
    STANDARD = %w[
      SIGABRT SIGALRM SIGBUS SIGCHLD SIGCLD SIGCONT SIGFPE SIGHUP SIGILL SIGINT
      SIGIO SIGIOT SIGKILL SIGPIPE SIGPOLL SIGPROF SIGPWR SIGQUIT SIGSEGV SIGSTKFLT
      SIGSTOP SIGSYS SIGTERM SIGTRAP SIGTSTP SIGTTIN SIGTTOU SIGURG SIGUSR1 SIGUSR2
      SIGVTALRM SIGWINCH SIGXCPU SIGXFSZ
    ].freeze
    REALTIME = %w[SIGRTMIN SIGRTMAX].concat(
      (1..15).map { |offset| "SIGRTMIN+#{offset}" },
      (1..14).map { |offset| "SIGRTMAX-#{offset}" }
    ).freeze
    LINUX = (STANDARD + REALTIME).sort.freeze
    WINDOWS = %w[SIGKILL SIGTERM].freeze
    CRI_NAMES = LINUX.to_h { |name| [name, name.gsub("+", "PLUS").gsub("-", "MINUS")] }.freeze
    API_NAMES = CRI_NAMES.invert.freeze

    module_function

    def custom_signal(container)
      lifecycle = container["lifecycle"]
      lifecycle["stopSignal"] if lifecycle.is_a?(Hash)
    end

    def cri_name(name)
      CRI_NAMES[name]
    end

    def api_name(name)
      API_NAMES[name.to_s]
    end
  end
end
