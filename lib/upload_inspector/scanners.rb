# frozen_string_literal: true

module UploadInspector
  # Malware scanners run after the structural check, on files it accepted (see the +scanner:+
  # option of UploadInspector.check). A scanner is any object with
  #
  #   scan(path) # => :clean | [:infected, signature]; raises when it cannot scan
  #
  # It runs in this process, outside the sandbox (it usually needs a socket), so it must bound
  # its own time: both adapters here take +timeout:+.
  module Scanners
    # Raised by the adapters when the scanner cannot give a verdict (unreachable, timeout, limit).
    class Error < StandardError; end

    # Raised by check_s3(require_guardduty_tag: true) while GuardDuty has not tagged the object
    # yet, so a job retries later instead of judging an unscanned file.
    class Pending < StandardError; end

    module_function

    # [reason, detail] for a scanner rejection, nil when clean. Never raises: any error or an
    # unexpected return value is :scanner_failed (the caller decides whether that fails open).
    def verdict(scanner, path)
      case (outcome = scanner.scan(path))
      in :clean then nil
      in [:infected, signature] then [:malware_detected, signature.to_s]
      else [:scanner_failed, "unexpected scanner result: #{outcome.inspect[0, 100]}"]
      end
    rescue StandardError => e
      [:scanner_failed, "#{e.class}: #{e.message}"[0, 200]]
    end
  end
end

require_relative 'scanners/clamav'
require_relative 'scanners/command'
