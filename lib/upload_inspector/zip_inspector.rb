# frozen_string_literal: true

require 'tmpdir'

module UploadInspector
  # Validates zip containers. OOXML documents are checked part by part; plain archives
  # have every member extracted (size-bounded, to a temp dir) and inspected with the same
  # policy. Archives inside archives are rejected.
  class ZipInspector
    include Rejectable

    OOXML_TYPES = %w[
      application/vnd.openxmlformats-officedocument.wordprocessingml.document
      application/vnd.openxmlformats-officedocument.presentationml.presentation
      application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
    ].freeze
    NESTED_ARCHIVE = /\.(?:zip|7z|rar|gz|tgz|bz2|xz|zst|tar|jar|war|ear|apk|ipa|cab|iso|img|dmg|vhdx?|arj|lzh|lha|z)\z/i
    READ_CHUNK_SIZE = 64 * 1024
    RATIO_CHECK_MIN_SIZE = MEGABYTE # tiny files compress extremely well legitimately

    def initialize(policy, depth:)
      @policy = policy
      @depth = depth
    end

    def verify!(path, detected_type)
      Zip::File.open(path) do |zip|
        entries = zip.entries
        check_entries!(entries)
        if OOXML_TYPES.include?(detected_type)
          OoxmlInspector.new(policy, self).verify!(entries)
        else
          verify_archive_members!(entries)
        end
      end
    rescue Zip::Error => e
      reject!(:zip_unparsable, e.message)
    end

    # Reads a member fully into memory, never beyond +limit+ or its declared size.
    def read_bounded(entry, limit)
      reject!(:zip_inflate_limit, entry.name) if entry.size > limit
      data = +''.b
      each_chunk(entry) do |chunk|
        data << chunk
        reject!(:zip_inflate_limit, entry.name) if data.bytesize > limit
      end
      data
    end

    # First bytes of a member, to tell what it really is without inflating all of it.
    def read_head(entry, length)
      entry.get_input_stream { |io| io.read(length) }.to_s.b
    end

  private

    attr_reader :policy, :depth

    def check_entries!(entries)
      reject!(:zip_empty) if entries.empty?
      reject!(:zip_too_many_entries, entries.size.to_s) if entries.size > policy.max_zip_entries
      names = entries.map { |e| e.name.to_s.downcase }
      reject!(:zip_duplicate_entry) if names.uniq.size != names.size

      total = 0
      entries.each do |entry|
        check_entry!(entry)
        total += entry.size.to_i
        reject!(:zip_too_large, 'total uncompressed size') if total > policy.max_zip_total_size
      end
    end

    def check_entry!(entry)
      check_path!(entry.name.to_s)
      reject!(:zip_encrypted_entry, entry.name) if entry.gp_flags.to_i.anybits?(1)
      reject!(:zip_unsafe_path, "symlink #{entry.name}") if entry.symlink?
      reject!(:zip_too_large, entry.name) if entry.size.to_i > policy.max_zip_entry_size
      check_ratio!(entry)
    end

    def check_path!(name)
      unsafe = name.empty? || name.include?("\0") || name.include?('\\') || name.start_with?('/') ||
               name.match?(/\A[A-Za-z]:/) || name.split('/').include?('..')
      reject!(:zip_unsafe_path, name.inspect) if unsafe
    end

    def check_ratio!(entry)
      size = entry.size.to_i
      return if size < RATIO_CHECK_MIN_SIZE

      compressed = entry.compressed_size.to_i
      return if compressed.positive? && size / compressed <= policy.max_compression_ratio

      reject!(:zip_bomb, "#{entry.name} ratio exceeds #{policy.max_compression_ratio}")
    end

    def verify_archive_members!(entries)
      reject!(:nested_archive, 'archive inside archive') if depth.positive?

      Dir.mktmpdir('upload_inspector') do |dir|
        entries.reject(&:directory?).each_with_index do |entry, index|
          reject!(:nested_archive, entry.name) if entry.name.match?(NESTED_ARCHIVE)
          member_path = File.join(dir, "member-#{index}")
          extract_bounded!(entry, member_path)
          verify_member!(member_path, entry.name)
          File.delete(member_path)
        end
      end
    end

    def verify_member!(member_path, name)
      Inspector.new(policy, depth: depth + 1).verify!(member_path, File.basename(name))
    rescue Rejection => e
      raise Rejection.new(e.reason, [name, e.detail].compact.join(': '))
    end

    # Actual inflated bytes must match the declared size (no lying headers).
    def extract_bounded!(entry, destination)
      written = 0
      File.open(destination, 'wb') do |out|
        each_chunk(entry) do |chunk|
          written += chunk.bytesize
          reject!(:zip_size_mismatch, entry.name) if written > entry.size.to_i
          out.write(chunk)
        end
      end
      reject!(:zip_size_mismatch, entry.name) if written != entry.size.to_i
    end

    def each_chunk(entry)
      entry.get_input_stream do |io|
        while (chunk = io.read(READ_CHUNK_SIZE)) && !chunk.empty?
          yield chunk
        end
      end
    end
  end
end
