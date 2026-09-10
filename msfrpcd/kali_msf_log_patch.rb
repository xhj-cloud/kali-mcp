# -*- coding: binary -*-
#
# kali-mcp: capture msfrpcd module print output to a log file.
#
# WHY THIS EXISTS
# Under msfrpcd, modules have user_output == nil — nothing ever calls
# init_ui with a real output (unlike msfconsole's terminal shell).
# Rex::Ui::Subscriber print_* methods silently no-op when user_output
# is nil, so ALL module output (ssh_login lines, scan results, exploit
# banners) is discarded by the framework. Verified 2026-09-10 by
# strace + fd inspection: no write syscall ever carries module output.
#
# WHAT THIS DOES
# Loaded via RUBYOPT=-r<absolute path> in the msfrpcd systemd unit.
# A watcher thread waits for the Msf::Simple classes to load, then
# wraps their singleton entry points (run_simple / exploit_simple) to
# inject a file-backed LocalOutput. Msf::Simple::*.{run,exploit}_simple
# do: mod.init_ui(opts['LocalInput'] || mod.user_input,
# opts['LocalOutput'] || mod.user_output) — so the injected handle
# receives every print_* call. Rex::Ui::Text::Output::File flushes on
# every write, so output lands in the file in real time.
#
# Output file: ENV['MSF_RPC_LOG_FILE'] or
# /var/log/metasploit-framework/msfrpcd.log — the same file the
# systemd unit appends stdout+stderr to (StandardOutput=append:).
# The MCP tool `msf_log` reads that file.
#
# Failure is soft: if anything here breaks, module output is discarded
# exactly like before (no crash, no behavior change).

require 'thread'

module KaliMsfLog
  LOG_PATH = ENV['MSF_RPC_LOG_FILE'] || '/var/log/metasploit-framework/msfrpcd.log'

  # Lazy: the Rex output classes are not loaded at RUBYOPT preload time.
  def self.output
    @output ||= begin
      require 'rex/ui/text/output/file'
      Rex::Ui::Text::Output::File.new(LOG_PATH, 'ab')
    rescue StandardError
      nil
    end
  end

  # Wrap a singleton method (omod, opts, &block) to inject LocalOutput.
  def self.patch(mod, method_name)
    return unless mod.respond_to?(method_name, true)
    return if mod.instance_variable_get(:"@kali_msf_log_patched_#{method_name}")
    orig = mod.method(method_name)
    mod.instance_variable_set(:"@kali_msf_log_patched_#{method_name}", true)
    mod.define_singleton_method(method_name) do |omod, opts = {}, &block|
      handle = KaliMsfLog.output
      if handle
        opts = opts.dup
        opts['LocalOutput'] ||= handle
      end
      orig.call(omod, opts, &block)
    end
  end
end

# The MSF classes do not exist at RUBYOPT preload time; apply the patch
# as soon as they appear (long before any RPC job can run).
Thread.new do
  patched = 0
  loop do
    begin
      if defined?(Msf::Simple::Auxiliary)
        KaliMsfLog.patch(Msf::Simple::Auxiliary, :run_simple)
        patched += 1
      end
      if defined?(Msf::Simple::Exploit)
        KaliMsfLog.patch(Msf::Simple::Exploit, :exploit_simple)
        patched += 1
      end
      if defined?(Msf::Simple::Post)
        KaliMsfLog.patch(Msf::Simple::Post, :run_simple)
        patched += 1
      end
      break if patched >= 3
    rescue NameError, StandardError
      # still loading / soft failure — keep waiting or give up silently
    end
    sleep 0.05
  end
end
