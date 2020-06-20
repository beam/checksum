#!/usr/bin/env ruby

require 'openssl'
require 'zlib'

module Zlib; module Digest; class CRC32
    def update(chucnk); @crc32 = Zlib.crc32(chucnk, @crc32) end
    def hexdigest; @crc32.to_s(16); end
end; end; end

class File; 
  def each_chunk(chunk_size); yield read(chunk_size) until eof? ;end
end

CHUNK_SIZE = 1024 * 1024

DIGEST_DEFS = [
  {
    title: "MD5",
    regexp: [
      /^(?<digest>[a-f0-9]{32}) \*(?<filename>.+)/i,
      /^(?<digest>[a-f0-9]{32}) (?<filename>.+)/i,
      /^MD5 \((?<filename>.+)\) = (?<digest>[a-f0-9]{32})/i,
    ],
    suffix: [".md5"],
    digest: OpenSSL::Digest::MD5
  },
  {
    title: "SHA1",
    regexp: [
      /^(?<digest>[a-f0-9]{40}) \*(?<filename>.+)/i,
      /^(?<digest>[a-f0-9]{40}) (?<filename>.+)/i,
      /^SHA1 \((?<filename>.+)\) = (?<digest>[a-f0-9]{40})/i,
    ],
    suffix: [".sha"],
    digest: OpenSSL::Digest::SHA1
  },
  {
    title: "CRC32",
    regexp: [
      /^(?<filename>.+) (?<digest>[a-f0-9]{8})/i,
    ],
    suffix: [".sfv", ".crc"],
    digest: Zlib::Digest::CRC32
  },
  {
    title: "SHA224",
    regexp: [
      /^(?<digest>[a-f0-9]{56}) \*(?<filename>.+)/i,
      /^(?<digest>[a-f0-9]{56}) (?<filename>.+)/i,
      /^SHA224 \((?<filename>.+)\) = (?<digest>[a-f0-9]{56})/i,
    ],
    suffix: [".sha224"],
    digest: OpenSSL::Digest::SHA224
  },
  {
    title: "SHA256",
    regexp: [
      /^(?<digest>[a-f0-9]{64}) \*(?<filename>.+)/i,
      /^(?<digest>[a-f0-9]{64}) (?<filename>.+)/i,
      /^SHA256 \((?<filename>.+)\) = (?<digest>[a-f0-9]{64})/i,
    ],
    suffix: [".sha256"],
    digest: OpenSSL::Digest::SHA256
  },
  {
    title: "SHA384",
    regexp: [
      /^(?<digest>[a-f0-9]{96}) \*(?<filename>.+)/i,
      /^(?<digest>[a-f0-9]{96}) (?<filename>.+)/i,
      /^SHA384 \((?<filename>.+)\) = (?<digest>[a-f0-9]{96})/i,
    ],
    suffix: [".sha384"],
    digest: OpenSSL::Digest::SHA384
  },
  {
    title: "SHA512",
    regexp: [
      /^(?<digest>[a-f0-9]{128}) \*(?<filename>.+)/i,
      /^(?<digest>[a-f0-9]{128}) (?<filename>.+)/i,
      /^SHA512 \((?<filename>.+)\) = (?<digest>[a-f0-9]{128})/i,
    ],
    suffix: [".sha512"],
    digest: OpenSSL::Digest::SHA512
  },
]

def output_line(digest_name, filename, state, payload = {})
  print "\u001b[34m"
  print "[#{digest_name}]".ljust(9," ")
  finish = true
  case state
  when :not_found
    print "\u001b[36;1m"
    print "[NOT FOUND]".ljust(14," ")
  when :check
    finish = false
    print "\u001b[33m"
    print "[CHECK #{payload[:progress]}%]".ljust(14," ")
  when :success
    print "\u001b[32;1m"
    print "[SUCCESS]".ljust(14," ")
  when :failed
    print "\u001b[31;1m"
    print "[FAILED]".ljust(14," ")
  end
  print "\u001b[37;1m"
  print "#{filename}"
  if payload[:progress_size]
    print "\u001b[35;1m"
    progress_time = payload[:progress_time] > 0 ? payload[:progress_time] : 1
    print " (#{((payload[:progress_size].to_f / progress_time)/1024/1024).round(2)} MB/s)" + " " * 5
  end
  print "\u001b[0m"
  print finish ? "\n" : "\r" 
end

def check_digest(definition, found_digest, search_path = ".")
  found_full_filename = File.join(search_path, found_digest[:filename])
  unless File.exists?(found_full_filename)
    output_line(definition[:title], found_digest[:filename], :not_found)
    return false
  end
  total_size = File.size(found_full_filename)
  progress_size = 0
  digester = definition[:digest].new
  start_time = Time.now.to_i
  File.open(found_full_filename, "rb").each_chunk(CHUNK_SIZE) do |chunk|
    progress_size += chunk.size
    digester.update chunk
    output_line(definition[:title], found_digest[:filename], :check, { progress: ((progress_size.to_f / total_size) * 100).to_i , progress_size: progress_size, progress_time: Time.now.to_i - start_time })
  end
  result = digester.hexdigest.downcase == found_digest[:digest].downcase
  output_line(definition[:title], found_digest[:filename], result ? :success : :failed, { progress_size: total_size, progress_time: Time.now.to_i - start_time })
  return result
end

def detect_digest_by_suffix(filename)
  checksum_file_suffix = File.extname(filename).downcase
  DIGEST_DEFS.each { |definition| return definition if definition[:suffix] && definition[:suffix].include?(checksum_file_suffix) }
  return nil
end

def find_digest(file_line, digest_def)
  digest_def[:regexp].each { |regexp|
      match_result = file_line.strip.match(regexp)
      return { orig_filename: match_result[:filename], digest: match_result[:digest], filename: match_result[:filename].gsub(/[\/\\]/,File::SEPARATOR) } if match_result
  }
  return nil
end

checksum_file = ARGV.first
raise "File not found" unless (checksum_file and File.exists?(checksum_file))

File.open(checksum_file, "r").each_line do |checksum_line| 
  next if checksum_line.match(/^;/)
  digest_def = detect_digest_by_suffix(checksum_file)
  digest_defs = digest_def ? [digest_def].push(DIGEST_DEFS).flatten.uniq: DIGEST_DEFS
  digest_defs.each { |definition|
    found_digest = find_digest(checksum_line, definition)
    if found_digest
      check_digest(definition, found_digest, File.dirname(checksum_file))
      break
    end
  }
end