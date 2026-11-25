# frozen_string_literal: true

require 'test_helper'
require 'sample_virus_malware'

class SanitizeTest < Minitest::Test
  include FixtureBuilder

  S = SampleVirusMalware
  POLICY = UploadInspector::Policy.new(allowed_types: S::IMAGES)

  def walk(type, bytes)
    blocks = []
    UploadInspector::ImageInspector.new(POLICY).verify!(write_file('w', bytes), type) { |*block| blocks << block }
    blocks
  end

  # Rewriters copy blocks byte for byte, so the walker must account for every byte, in order.
  def test_image_walker_blocks_tile_the_file
    { 'image/png' => S.png, 'image/jpeg' => S.jpeg + S.jpeg, 'image/gif' => S.gif, 'image/webp' => S.webp }.each do |type, bytes|
      blocks = walk(type, bytes)
      position = 0
      blocks.each do |_, offset, length|
        assert_equal position, offset, "#{type} gap before #{blocks.inspect}"
        position += length
      end
      assert_equal bytes.bytesize, position, type
    end
  end

  def test_image_walker_block_kinds
    assert_equal [:signature, 'IHDR', 'IDAT', 'IEND'], walk('image/png', S.png).map(&:first)
    assert_equal [0xD8, 0xE0, 0xC0, 0xDA, :scan_data, 0xD9], walk('image/jpeg', S.jpeg).map(&:first)
    assert_equal %i[header image trailer], walk('image/gif', S.gif).map(&:first)
    assert_equal [:riff, 'VP8L'], walk('image/webp', S.webp).map(&:first)
  end
end
