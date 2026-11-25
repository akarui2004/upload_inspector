# frozen_string_literal: true

module UploadInspector
  module Sanitizers
    # Decodes a raster image with libvips and encodes a new one (sanitize reencode: true). The
    # strongest option: nothing of the original file survives but its pixels, so a payload
    # hidden in pixel or entropy-coded data is gone too. Needs the ruby-vips gem and libvips;
    # neither is a dependency of this gem, ruby-vips is loaded only when reencode is asked for.
    #
    # The loader is chosen from the detected type (never sniffed by libvips) and libvips'
    # untrusted loaders are blocked. Metadata is stripped; an embedded color profile is applied
    # first (output in sRGB) and, with keep_orientation, the EXIF orientation is applied to the pixels.
    module VipsReencoder
      LOADERS = {
        'image/png' => :pngload, 'image/jpeg' => :jpegload, 'image/gif' => :gifload, 'image/webp' => :webpload,
        'image/heic' => :heifload, 'image/heif' => :heifload, 'image/avif' => :heifload,
      }.freeze
      SUFFIXES = {
        'image/png' => '.png', 'image/jpeg' => '.jpg', 'image/gif' => '.gif', 'image/webp' => '.webp',
        'image/heic' => '.heic', 'image/heif' => '.heic', 'image/avif' => '.avif',
      }.freeze
      ANIMATED = %w[image/gif image/webp].freeze

      module_function

      def type?(type) = LOADERS.key?(type)

      # Raises ArgumentError when ruby-vips or libvips cannot be loaded.
      def require_vips!
        require 'vips'
        Vips.block_untrusted(true) if Vips.respond_to?(:block_untrusted)
      rescue LoadError => e
        raise ArgumentError, "reencode: true needs the ruby-vips gem and libvips (#{e.message})"
      end

      # Writes a re-encoded copy of +path+ (detected +type+) to +output+. The check limits each
      # frame to max_image_pixels; decoding every frame of an animation is limited in total.
      def reencode(path, type, output, max_pixels:, keep_orientation: false)
        require_vips!
        options = { fail_on: :error }
        options[:n] = -1 if ANIMATED.include?(type) # every frame, stacked vertically
        image = Vips::Image.public_send(LOADERS.fetch(type), path, **options) # reads the header only
        if image.width * image.height > max_pixels
          raise Rejection.new(:image_too_many_pixels, "#{image.width}x#{image.height} decoded pixels exceed #{max_pixels}")
        end

        image = image.icc_transform('srgb', embedded: true) if image.get_typeof('icc-profile-data').positive?
        image = image.autorot if keep_orientation
        encoded = output + SUFFIXES.fetch(type) # libvips picks the encoder from the suffix
        image.write_to_file(encoded, strip: true)
        File.rename(encoded, output)
      end
    end
  end
end
