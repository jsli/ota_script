#!/usr/bin/env ruby
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program in the file COPYING.
#  If not, see <http://www.gnu.org/licenses/>.

# XXX:
# this script depends on two files: timbuilder.rb and rsa_private_key.pem.
# If you want to get a standalone tool by moving it around, make sure copy
# the two files along with you and fix the relative pathname below.
Timbuilder = "./timbuilder.rb"
Rsaprivkey = "./rsa_private_key.pem"

require_relative "#{Timbuilder}"
require 'bindata'

# Usage
Scriptname = File.basename($0)
Usage = "                                                                   \n" +
        " SYNOPSIS                                                          \n" +
        "        #{Scriptname} dtim image1 [image2...]                      \n" +
        "                                                                   \n" +
        " DESCRIPTION                                                       \n" +
        "        #{Scriptname} is a program for re-sign a dtim. The first   \n" +
        "        argument is the file contains dtim. The remains are image  \n" +
        "        files that will be hashed and appended to the result.      \n" +
        "                                                                   \n" +
        " EXAMPLES                                                          \n" +
        "        Re-sign a radio dtim and generate a combined Radio.img     \n" +
        "                                                                   \n" +
        "        $ #{Scriptname} path/to/Radio.dtim p/seagull.bin p/msa.bin \n" +
        "                                                                   \n" +
        "        Re-sign a boot.img. The first argument is the boot.img     \n" +
        "         contains dtim. The second argument is the raw boot image  \n" +
        "         that does not have a dtim header.                         \n" +
        "                                                                   \n" +
        "        $ #{Scriptname} path/to/boot.img path/to/raw/boot.img      \n" +
        "                                                                   \n"

class BinVersionI < BinData::Record
  endian :little
  uint32 :version
  uint32 :identifier
  uint32 :trusted
  uint32 :issue_date
  uint32 :oem_unique_id
end

class BinFlashI < BinData::Record
  endian :little
  uint32 :wtm_flash_sign
  uint32 :wtm_entry_addr
  uint32 :wtm_entry_addr_back
  uint32 :wtm_patch_sign
  uint32 :wtm_patch_addr
  uint32 :boot_flash_sign
end

class BinCTim < BinData::Record
  endian        :little
  bin_version_i :version_bind
  bin_flash_i   :flash_info
  uint32        :num_images
  uint32        :num_keys
  uint32        :size_of_reserved
end

class BinImageInfo_3_4_0 < BinData::Record
  endian :little
  uint32 :image_id
  uint32 :next_image_id
  uint32 :flash_entry_addr
  uint32 :load_addr
  uint32 :image_size
  uint32 :image_size_to_hash
  uint32 :hash_algorithm_id
  array  :hashv, :type => :uint32, :read_until => lambda { index == 15 }
  uint32 :partition_number
end

class ReSignDtim
  def initialize(argv)
    @argv = argv

    @dtim_plat_ds = nil
    @dtim_rsa_private_key = nil
    @dtim_key_mods = nil

    @bin_ctim = nil
    @bin_img_info = Array.new
    @is_radio = false
    @radio_info = Array.new
    @ofile = nil
  end

  def get_ds(data, hash_algm, private_key)
    sha_name = nil
    case hash_algm
      when 'SHA-160', TimConsts::HASH_ALGORITHM_ID_T['SHA-160']
        sha_name = 'SHA1'
      when 'SHA-256', TimConsts::HASH_ALGORITHM_ID_T['SHA-256']
        sha_name = 'SHA256'
      when 'SHA-512', TimConsts::HASH_ALGORITHM_ID_T['SHA-512']
        sha_name = 'SHA512'
      else
        raise "unsupported: #{hash_algm}"
    end
    ds = private_key.sign(sha_name, data)
    return (ds.reverse).unpack('V*')
  end

  def get_hash(data, hash_algm)
    sha = nil
    case hash_algm
      when 'SHA-160', TimConsts::HASH_ALGORITHM_ID_T['SHA-160']
        sha = OpenSSL::Digest::SHA1.new
      when 'SHA-256', TimConsts::HASH_ALGORITHM_ID_T['SHA-256']
        sha = OpenSSL::Digest::SHA256.new
      when 'SHA-512', TimConsts::HASH_ALGORITHM_ID_T['SHA-512']
        sha = OpenSSL::Digest::SHA512.new
      else
        raise "unsupported: #{hash_algm}"
    end
    digest = sha.digest(data)
    return digest.unpack('V*')
  end

  def load_plat_ds
    max_rsa_keysize_words = TimConsts::MAX_RSA_KEYSIZE_WORDS
    plat_ds = PlatDs.new

    plat_ds.hash_algorithm_id = TimConsts::HASH_ALGORITHM_ID_T['SHA-160']
    plat_ds.ds_algorithm_id = TimConsts::ENCRYPT_ALGORITHM_ID_T['PKCS1_v1_5_Ippcp']
    plat_ds.key_size = 1024
    plat_ds.hash = [0]*8

    rsa_key = RsaKey.new
    rsa_key.load(`cat #{File.join(File.dirname($0), "#{Rsaprivkey}")}`)

    exponent_str = sprintf("%0#{plat_ds.key_size/4}X", rsa_key.get_key[1])
    exponent = [exponent_str].pack('H*').reverse.unpack('V*')

    modulus_str = sprintf("%0#{plat_ds.key_size/4}X", rsa_key.get_key[0])
    modulus = [modulus_str].pack('H*').reverse.unpack('V*')

    ds_rsa = DsRsa.new([0]*max_rsa_keysize_words, [0]*max_rsa_keysize_words, [0]*max_rsa_keysize_words)
    ds_rsa.rsa_public_exponent[0, exponent.size] = exponent
    ds_rsa.rsa_modulus[0, modulus.size] = modulus
    plat_ds.key = ds_rsa

    scheme = TimConsts::PKCSv1_SHA1_1024RSA

    data = scheme.to_bytes + (ds_rsa.rsa_modulus[0, plat_ds.key_size/8/4]).to_bytes + (ds_rsa.rsa_public_exponent[0, plat_ds.key_size/8/4]).to_bytes
    hash_result = get_hash(data, plat_ds.hash_algorithm_id)
    plat_ds.hash[0, hash_result.size] = hash_result

    @dtim_plat_ds = plat_ds
    @dtim_rsa_private_key = rsa_key
  end

  def load_key_mods
    max_rsa_keysize_words = TimConsts::MAX_RSA_KEYSIZE_WORDS
    key_mod = KeyMod_3_4_0.new

    key_mod.key_id = 'ENCK'.unpack('H*')[0].hex
    key_mod.hash_algorithm_id = TimConsts::HASH_ALGORITHM_ID_T['SHA-160']
    key_mod.encrypt_algorithm_id = TimConsts::ENCRYPT_ALGORITHM_ID_T['PKCS1_v1_5_Ippcp'] | 0x80000000
    key_mod.key_size = 1024
    key_mod.public_key_size = 1024

    key_rsa = KeyEncryptedRsa.new([0]*max_rsa_keysize_words, [0]*max_rsa_keysize_words)
    ds = get_ds(@dtim_plat_ds.key.rsa_public_exponent[0, key_mod.public_key_size/8/4].to_bytes, key_mod.hash_algorithm_id, \
                @dtim_rsa_private_key)
    key_rsa.encrypted_hash_rsa_public_exponent[0, ds.size] = ds
    ds = get_ds(@dtim_plat_ds.key.rsa_modulus[0, key_mod.public_key_size/8/4].to_bytes, key_mod.hash_algorithm_id, \
                @dtim_rsa_private_key)
    key_rsa.encrypted_hash_rsa_modulus[0, ds.size] = ds
    key_mod.key = key_rsa

    key_mod.key_hash = [0]*16
    scheme = TimConsts::PKCSv1_SHA1_1024RSA
    data = scheme.to_bytes + (key_rsa.encrypted_hash_rsa_modulus[0, key_mod.key_size/8/4]).to_bytes + (key_rsa.encrypted_hash_rsa_public_exponent[0, key_mod.key_size/8/4]).to_bytes
    hash_result = get_hash(data, key_mod.hash_algorithm_id)
    key_mod.key_hash[0, hash_result.size] = hash_result

    @dtim_key_mods = key_mod
  end

  def get_backup(output)
    return nil if not File.exist?(output)

    i = 0;
    while backup = output + ".bak#{i}"
      return backup if not File.exist?(backup)
      i = i + 1
    end
  end

  def prepare
    # check argv size
    raise "argument error\n" +
           Usage if @argv.size == 0

    ifile = @argv[0]
    raise "argument error\n" +
          "\"#{ifile}\" does not exist" if not File.exist?(ifile)
    @argv.shift

    @ofile = @argv[0]
    @argv.shift

    # check file exist
    @argv.each do |argv|
      raise "argument error\n" +
            "\"#{argv}\" does not exist" if not File.exist?(argv)
    end

    File.open(ifile, "rb:ASCII-8BIT") do |file|
      @bin_ctim = BinCTim.read(file)

      # check dtim format
      if @bin_ctim.version_bind.version != 0x00030400 or @bin_ctim.version_bind.trusted != 0x1
        raise "argument error\n" +
              "\"#{@argv[0]}\" is not a trusted tim in version 3.4"
      end

      # check number of image
      if @bin_ctim.num_images-1 != @argv.size
        raise "argument error\n" +
              "tim contains: #{@bin_ctim.num_images-1} image(s)\n" +
              "you provide: #{@argv.size} image(s)"
      end

      @bin_ctim.num_images.times do
        @bin_img_info.push BinImageInfo_3_4_0.read(file)
      end

      @bin_img_info.each do |image|
        if (image.image_id & 0xffffff) == 0x524249  # *RBI
          @is_radio = true
        end
      end

      # check cp path
      if @is_radio
        file.seek(1024*3)
        orig_radio_info = file.read(1024).unpack("Z*")[0]
        orig_radio_info.each_line do |str|
          /(?<id>.*)\|(?<network>.*)\|(?<sim>.*)\|(?<path>.*)/ =~ str
          r_info = Hash.new
          r_info['id'] = id
          r_info['network'] = network
          r_info['sim'] = sim
          r_info['path'] = path
          r_info['path_root'] = path.gsub(/([^\/]*\/).*/, '\1.*')
          @radio_info.push r_info
        end
        @argv.each_index do |i|
          if /#{@radio_info[i]['path_root']}/ =~ @argv[i]
            @radio_info[i]['path'] = /#{@radio_info[i]['path_root']}/.match(@argv[i])[0]
          else
            raise "argument error\n" +
                  "cp path root does not match.\n" +
                  "tim contains: #{@radio_info[i]['path_root']}\n" +
                  "you provide: #{@argv[i]}"
          end
        end
      end
    end
  end

  def write_output
    version_i = VersionI.new
    version_i.version       = @bin_ctim.version_bind.version
    version_i.identifier    = @bin_ctim.version_bind.identifier
    version_i.trusted       = @bin_ctim.version_bind.trusted
    version_i.issue_date    = @bin_ctim.version_bind.issue_date
    version_i.oem_unique_id = @bin_ctim.version_bind.oem_unique_id

    flash_i = FlashI.new
    flash_i.wtm_flash_sign      = @bin_ctim.flash_info.wtm_flash_sign
    flash_i.wtm_entry_addr      = @bin_ctim.flash_info.wtm_entry_addr
    flash_i.wtm_entry_addr_back = @bin_ctim.flash_info.wtm_entry_addr_back
    flash_i.wtm_patch_sign      = @bin_ctim.flash_info.wtm_patch_sign
    flash_i.wtm_patch_addr      = @bin_ctim.flash_info.wtm_patch_addr
    flash_i.boot_flash_sign     = @bin_ctim.flash_info.boot_flash_sign

    c_tim = CTim.new
    c_tim.version_bind = version_i
    c_tim.flash_info = flash_i
    c_tim.num_images = @bin_ctim.num_images
    c_tim.num_keys = @bin_ctim.num_keys
    c_tim.size_of_reserved = @bin_ctim.size_of_reserved

    image_infos = Array.new
    @bin_ctim.num_images.times do |i|
      image_info = ImageInfo_3_4_0.new

      image_info.image_id = @bin_img_info[i].image_id
      image_info.next_image_id = @bin_img_info[i].next_image_id
      image_info.load_addr = @bin_img_info[i].load_addr
      image_info.hash_algorithm_id = @bin_img_info[i].hash_algorithm_id
      image_info.partition_number = @bin_img_info[i].partition_number

      image_info.hash = [0]*16
      if i == 0
        image_info.image_size = @bin_img_info[i].image_size
        image_info.image_size_to_hash = @bin_img_info[i].image_size_to_hash
        image_info.flash_entry_addr = @bin_img_info[i].flash_entry_addr
        16.times do |j|
          image_info.hash[j] = @bin_img_info[i].hashv[j]
        end
      else
        image_info.image_size = File.size(@argv[i-1])
        image_info.image_size_to_hash = image_info.image_size
        image_info.flash_entry_addr = image_infos[i-1].flash_entry_addr + ((image_infos[i-1].image_size + 4095) / 4096 * 4096) / 0x200
        hash_result = get_hash(File.binread(@argv[i-1]), image_info.hash_algorithm_id)
        image_info.hash[0, hash_result.size] = hash_result
      end

      image_infos << image_info
    end

    load_plat_ds()
    load_key_mods()

    key_mods = @dtim_key_mods
    reserved = []
    plat_ds = @dtim_plat_ds

    tim = Tim.new(c_tim, image_infos, key_mods, reserved, plat_ds)
    ds = get_ds(tim.to_bytes[0, image_infos[0].image_size_to_hash], plat_ds.hash_algorithm_id, \
                @dtim_rsa_private_key)

    plat_ds.key.rsa_digs[0, ds.size] = ds

    backup = get_backup(@ofile)
    if backup
      puts "backup #{@ofile} to #{backup}"
      File.rename(@ofile, backup)
    end

    puts "write result to #{@ofile}"
    File.open(@ofile, "wb:ASCII-8BIT") do |file|
      file.write(tim.to_bytes)
      pad = 4096 - (file.pos % 4096)
      file.write(([0]*pad).pack("C*")) if pad !=4096
      if @is_radio
        file.seek(1024*3)
        @radio_info.each do |ri|
          file.write(ri['id'] + "|" + ri['network'] + "|" + ri['sim'] + "|" + ri['path'] + "\n")
        end
        file.seek(4096)
      end
      @argv.each  do |argv|
        file.write(File.binread(argv))
        pad = 4096 - (file.pos % 4096)
        file.write(([0]*pad).pack("C*")) if pad !=4096
      end
    end
  end
end

resigndtim = ReSignDtim.new(ARGV)
resigndtim.prepare
resigndtim.write_output

