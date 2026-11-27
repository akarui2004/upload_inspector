# frozen_string_literal: true

require_relative 'integration_helper'
SHRINE = IntegrationHelper.load('shrine', 'shrine/storage/memory')
require 'sample_virus_malware'

class ShrineIntegrationTest < Minitest::Test
  include FixtureBuilder
  S = SampleVirusMalware

  if SHRINE
    class ImageUploader < Shrine
      self.storages = { cache: Shrine::Storage::Memory.new, store: Shrine::Storage::Memory.new }
      plugin :upload_inspector, allowed_types: %w[image/png application/pdf], sandbox: false, sanitize: true
      Attacher.validate { errors << 'too big' if file.size > 10_000 }
    end
  end

  def setup
    skip 'needs the shrine gem (Gemfile group :integration)' unless SHRINE
  end

  def attach(name, bytes)
    attacher = ImageUploader::Attacher.new
    attacher.assign(File.open(write_file(name, bytes), 'rb'))
    attacher
  end

  def test_validation_errors_join_the_validate_block
    attacher = attach('x.png', clean_pdf + ('%' * 10_000))
    assert_equal ['does not match its file extension', 'too big'], attacher.errors
    assert_equal :extension_mismatch, attacher.upload_inspector_result.reason
    assert_empty attach('a.pdf', clean_pdf).errors
  end

  def test_promote_stores_the_cleaned_copy
    png = S.png.byteslice(0, 33) + S.png_chunk('tEXt', "Comment\0<?php system($_GET[0]);") + S.png.byteslice(33..)
    attacher = attach('a.png', png)
    attacher.promote
    assert attacher.stored?
    assert_equal [S.png, 'a.png', S.png.bytesize], [attacher.file.read, attacher.file.original_filename, attacher.file.size]

    attacher = attach('a.pdf', clean_pdf)
    attacher.promote
    assert_equal clean_pdf, attacher.file.read # cannot be cleaned: stored as checked
  end
end
