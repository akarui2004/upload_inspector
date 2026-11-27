# frozen_string_literal: true

require_relative 'integration_helper'
CARRIERWAVE = IntegrationHelper.load('carrierwave')
require 'sample_virus_malware'

class CarrierWaveIntegrationTest < Minitest::Test
  include FixtureBuilder
  S = SampleVirusMalware

  if CARRIERWAVE
    class ImageUploader < CarrierWave::Uploader::Base
      include UploadInspector::CarrierWave

      storage :file
      process :upload_inspector_sanitize
      def upload_inspector_options = { allowed_types: %w[image/png application/pdf], sandbox: false }
    end
  end

  def setup
    skip 'needs the carrierwave gem (Gemfile group :integration)' unless CARRIERWAVE
    ImageUploader.root = tmp_path('cw')
  end

  def test_unsafe_file_is_an_integrity_error
    uploader = ImageUploader.new
    error = assert_raises(CarrierWave::IntegrityError) { uploader.cache!(File.open(write_file('x.png', clean_pdf))) }
    assert_equal 'does not match its file extension', error.message
    assert_equal :extension_mismatch, uploader.upload_inspector_result.reason
  end

  def test_cache_sanitizes_and_keeps_unsupported_types
    png = S.png.byteslice(0, 33) + S.png_chunk('tEXt', "Comment\0<?php system($_GET[0]);") + S.png.byteslice(33..)
    uploader = ImageUploader.new
    uploader.cache!(File.open(write_file('a.png', png)))
    assert_equal S.png, File.binread(uploader.current_path)

    uploader = ImageUploader.new
    uploader.cache!(File.open(write_file('a.pdf', clean_pdf)))
    assert_equal clean_pdf, File.binread(uploader.current_path)
  end
end
