# encoding: utf-8

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

require 'rubygems'
require 'openssl'
require 'net/http'
require 'base64'

#Rsa
class RsaKey
  Padding = {
    'MD2' => [0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02, 0x05, 0x00, 0x04, 0x10].pack('C*'),
    'MD5' => [0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10].pack('C*'),
    'SHA1' => [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14].pack('C*'),
    'SHA256' => [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20].pack('C*'),
    'SHA384' => [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30].pack('C*'),
    'SHA512' => [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40].pack('C*'),
  }

  #calculate p from n,e,d
  def self.RsaFactor(n, e, d)
    x = e * d - 1
    y = ~x & (x - 1)
    s = 0
    while y != 0
      y >>= 1
      s += 1
    end
    r = x >> s
    puts "ed - 1 = 2^#{s}*#{r}"
    0.upto(1000) do
      w = Random.rand(n - 1) + 1
      x = w.gcd(n)
      puts "w=#{w} gcd=#{x}"
      if x > 1
        return x
      end
      v = PowerMode(w, r, n)
      puts "v=#{v}"
      if v == 1
        puts 'v == 1 continue'
        next
      end
      while v != 1
        v0 = v
        v = (v ** 2) % n
      end
      puts "v0=#{v0}"
      if (v0 + 1) % n == 0
        puts '(v0 + 1) % n == 0 continue'
        next
      else
        return (v0 + 1).gcd(n)
      end
    end
    return nil
  end

  #calculate x^e mod m
  def self.PowerMode(x, e, m)
    s = e.to_s(2)
    l = s.length
    z = 1
    0.upto(l-1) do |i|
      z = (z **2) % m
      if s[i] == '1'
        z = (z * x) % m
      end
    end
    return z
  end

  #calculate (b^-1) mod a
  def self.MultiplicativeInverse(a, b)
    a0 = a
    b0 = b
    t0 = 0
    t  = 1
    q  = a0 / b0
    r = a0 - q*b0
    while r > 0
      temp = (t0 - q*t) % a
      t0 = t
      t  = temp
      a0 = b0
      b0 = r
      q  = a0 / b0
      r  = a0 - q*b0
    end
    if b0 == 1
      return t
    else
      return nil
    end
  end

  def initialize
    @key = nil
    @keyBitLen = nil
    @is_private = false
    @n = nil
    @e = nil
    @d = nil
    @p = nil
    @q = nil
    @dp = nil
    @dq = nil
    @iqmodp = nil
  end

  def load(rsaKey)
    body = ''
    rsaKey.each_line do |line|
      if line.start_with? '----'
        next
      else
        body << line
      end
    end
    der = Base64.decode64(body)
    asn1 = OpenSSL::ASN1.decode(der)
    count = -1
    int_ary = []
    OpenSSL::ASN1.traverse(asn1) do | depth, offset, header_len, length, constructed, tag_class, tag|
      if depth == 1
        count += 1
        if tag == OpenSSL::ASN1::INTEGER
          int_ary << count
        end
      end
    end
    if int_ary.size == 2
      @is_private = false
      @n = asn1.value[int_ary[0]].value.to_i
      @e = asn1.value[int_ary[1]].value.to_i
      @keyBitLen = @n.size * 8
      @key = OpenSSL::PKey::RSA::new(self.public_key_to_pem)
    elsif int_ary.size == 9
      @is_private = true
      @n = asn1.value[int_ary[1]].value.to_i
      @e = asn1.value[int_ary[2]].value.to_i
      @d = asn1.value[int_ary[3]].value.to_i
      @p = asn1.value[int_ary[4]].value.to_i
      @q = asn1.value[int_ary[5]].value.to_i
      @dp = asn1.value[int_ary[6]].value.to_i
      @dq = asn1.value[int_ary[7]].value.to_i
      @iqmodp = asn1.value[int_ary[8]].value.to_i
      @keyBitLen = @n.size * 8
      @key = OpenSSL::PKey::RSA::new(self.private_key_to_pem)
    else
      puts 'error! unknown key format'
    end
  end

  def init_public_key(n, e)
    @is_private = false
    @n = n
    @e = e
    @d = nil
    @p = nil
    @q = nil
    @dp = nil
    @dq = nil
    @iqmodp = nil
    @key = OpenSSL::PKey::RSA::new(self.public_key_to_pem)
  end

  def init_private_key(n, e, d)
    @n = n
    @e = e
    @d = d
    @p = RsaFactor(n, e, d)
    if @p != nil
      @q = n / @p
      @dp = d % (p - 1)
      @dq = d % (q - 1)
      @iqmodp = MultiplicativeInverse(p, q)
      if @iqmodp != nil
        @key = OpenSSL::PKey::RSA::new(self.private_key_to_pem)
        @is_private = true
      end
    end
    if @is_private == false
      init_public_key(n, e)
    end
  end

  def get_key
    return [@n, @e, @d]
  end

  def private?
    return @is_private
  end

  def sign(digest_algorithm, data)
    if @is_private
      digest = OpenSSL::Digest::digest(digest_algorithm, data)
      padding = Padding[digest_algorithm]
      return @key.private_encrypt(padding + digest)
    else
      puts 'RsaKey: I am public key, can only sign with private key'
      return nil
    end
  end

  def verify(digest_algorithm, data, signature)
    old = @key.public_decrypt(signature)
    digest = OpenSSL::Digest::digest(digest_algorithm, data)
    padding = Padding[digest_algorithm]
    new = padding + digest
    return new == old
  end

  def to_s
    puts 'key bit len=' + @keyBitLen.to_s
    puts 'modulus=' + @n.to_s(16)
    puts 'publicExponent=' + @e.to_s(16)
    if @is_private
      puts 'privateExponent=' + @d.to_s(16)
      puts 'prime1=' + @p.to_s(16)
      puts 'prime2=' + @q.to_s(16)
      puts 'exponent1=' + @dp.to_s(16)
      puts 'exponent2=' + @dq.to_s(16)
      puts 'coefficient=' + @n.to_s(16)
    end
  end

  def public_key_to_pem
    modulus = OpenSSL::ASN1::Integer.new(@n)
    publicExponent = OpenSSL::ASN1::Integer.new(@e)
    sequence = OpenSSL::ASN1::Sequence.new([modulus, publicExponent])
    der = sequence.to_der
    pem = "-----BEGIN RSA PUBLIC KEY-----\n"
    pem << Base64.encode64(der)
    pem << "-----END RSA PUBLIC KEY-----"
    return pem
  end

  def private_key_to_pem
    if @is_private
      version = OpenSSL::ASN1::Integer.new(0)
      modulus = OpenSSL::ASN1::Integer.new(@n)
      publicExponent = OpenSSL::ASN1::Integer.new(@e)
      privateExponent = OpenSSL::ASN1::Integer.new(@d)
      prime1 = OpenSSL::ASN1::Integer.new(@p)
      prime2 = OpenSSL::ASN1::Integer.new(@q)
      exponent1 = OpenSSL::ASN1::Integer.new(@dp)
      exponent2 = OpenSSL::ASN1::Integer.new(@dq)
      coefficient = OpenSSL::ASN1::Integer.new(@iqmodp)
      sequence = OpenSSL::ASN1::Sequence.new([version, modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient])
      der = sequence.to_der
      pem = "-----BEGIN RSA PRIVATE KEY-----\n"
      pem << Base64.encode64(der)
      pem << "-----END RSA PRIVATE KEY-----"
      return pem
    else
      puts 'RsaKey: I am not private key'
      return nil
    end
  end
end


#TimBuilder
class Integer
  def to_bytes
    bytes = [self].pack('V')
    bytes.force_encoding('ASCII-8BIT')
  end
end

class Array
  def to_bytes
    bytes = ""
    bytes.force_encoding('ASCII-8BIT')
    self.each do |elem|
      if elem.respond_to?(:to_bytes)
          bytes << elem.to_bytes
      end
    end
    bytes.force_encoding('ASCII-8BIT')
  end
end

class Struct
  def to_bytes
    bytes = ""
    bytes.force_encoding('ASCII-8BIT')
    self.each do |elem|
      if elem.respond_to?(:to_bytes)
          bytes << elem.to_bytes
      end
    end
    bytes.force_encoding('ASCII-8BIT')
  end
end

class PackagePadding
  def initialize(bytesize)
    @bytesize = bytesize
  end

  def to_bytes
    bytes = ""
    bytes.force_encoding('ASCII-8BIT')
    if @bytesize > 0
      bytes = 0.chr * @bytesize
    end
    bytes.force_encoding('ASCII-8BIT')
  end
end

#constants and structs here should be consistent with obm

class TimConsts
    VERSION = 0x00030400
    HASH_ALGORITHM_ID_T = {
      'SHA-160' => 0x00000014,
      'SHA-256' => 0x00000020,
      'SHA-512' => 0x00000040
    }

    ENCRYPT_ALGORITHM_ID_T = {
      'Marvell_DS'       => 0x00000000,
      'PKCS1_v1_5_Caddo' => 0x00000001,
      'PKCS1_v2_5_Caddo' => 0x00000002,
      'PKCS1_v1_5_Ippcp' => 0x00000003,
      'PKCS1_v2_5_Ippcp' => 0x00000004,
      'ECDSA_256'        => 0x00000005,
      'ECDSA_512'        => 0x00000006
    }

    TIM_ID = 'TIMH'.unpack('H*')[0].hex
    WTP_RESERVED_AREA_ID = 'OPTH'.unpack('H*')[0].hex
    UART_ID = 'UART'.unpack('H*')[0].hex
    IMAP_ID = 'IMAP'.unpack('H*')[0].hex
    PRODUCT_ID = 'PROI'.unpack('H*')[0].hex
    FUNC_CONFIG_ID = 'FCNF'.unpack('H*')[0].hex
    CIDP_ID = 'CIDP'.unpack('H*')[0].hex
    TERMINATOR_ID = 'Term'.unpack('H*')[0].hex
    MAX_RSA_KEYSIZE_WORDS = 64

    DDR_OPERATION = {
      'DDR_NOP'                => 0,
      'DDR_INIT_ENABLE'        => 1,
      'DDR_MEMTEST_ENABLE'     => 2,
      'DDR_MEMTEST_START_ADDR' => 3,
      'DDR_MEMTEST_SIZE'       => 4,
      'DDR_INIT_LOOP_COUNT'    => 5,
      'DDR_IGNORE_INST_TO'     => 6
    }

    DTIM_IMAGE_TYPE = {
      'PRIMARYIMAGE'           => 0,
      'RECOVERYIMAGE'          => 1,
      'CPIMAGE'                => 2,
      'CUSTMOZIEDIMAGE_TYPE1'  => 10,
      'CUSTMOZIEDIMAGE_TYPE2'  => 11,
      'CUSTMOZIEDIMAGE_TYPE3'  => 12,
      'CUSTMOZIEDIMAGE_TYPE4'  => 13,
      'CUSTMOZIEDIMAGE_TYPE5'  => 14,
      'CUSTMOZIEDIMAGE_TYPE6'  => 15,
      'CUSTMOZIEDIMAGE_TYPE7'  => 16,
      'CUSTMOZIEDIMAGE_TYPE8'  => 17,
      'CUSTMOZIEDIMAGE_TYPE9'  => 18,
      'CUSTMOZIEDIMAGE_TYPE10' => 19,
      'CUSTMOZIEDIMAGE_TYPE11' => 20,
      'CUSTMOZIEDIMAGE_TYPE12' => 21,
      'CUSTMOZIEDIMAGE_TYPE13' => 22,
      'CUSTMOZIEDIMAGE_TYPE14' => 23,
      'CUSTMOZIEDIMAGE_TYPE15' => 24,
      'CUSTMOZIEDIMAGE_TYPE16' => 25,
      'CUSTMOZIEDIMAGE_TYPE17' => 26,
      'CUSTMOZIEDIMAGE_TYPE18' => 27,
      'CUSTMOZIEDIMAGE_TYPE19' => 28,
      'CUSTMOZIEDIMAGE_TYPE20' => 29,
    }

    # PKCS#1v1.5 Digital Signature in security.h
    PKCSv1_SHA1_1024RSA   = 0x0000A100
    PKCSv1_SHA256_1024RSA = 0x0000A110
    PKCSv1_SHA1_2048RSA   = 0x0000A200
    PKCSv1_SHA256_2048RSA = 0x0000A210
end

#TIM
class Tim < Struct.new("Tim", :cons_tim, :imgs, :keys, :reserved, :plat_ds)
end

#CTIM
class CTim < Struct.new("CTim", :version_bind, :flash_info, :num_images, :num_keys, :size_of_reserved)
end

class VersionI < Struct.new("VersionI", :version, :identifier, :trusted, :issue_date, :oem_unique_id)
end

class FlashI < Struct.new("FlashI", :wtm_flash_sign, :wtm_entry_addr, :wtm_entry_addr_back, :wtm_patch_sign, \
                                    :wtm_patch_addr, :boot_flash_sign)
end

#IMAGE_INFO_3_4_0
class ImageInfo_3_4_0 < Struct.new("ImageInfo_3_4_0", :image_id, :next_image_id, :flash_entry_addr, :load_addr, \
                                                      :image_size, :image_size_to_hash, :hash_algorithm_id, :hash, :partition_number)
end

#KEY_MOD_3_4_0
class KeyMod_3_4_0 < Struct.new("KeyMod_3_4_0", :key_id, :hash_algorithm_id, :key_size, :public_key_size, \
                                                :encrypt_algorithm_id, :key, :key_hash)
end

class KeyRsa < Struct.new("KeyRsa", :rsa_public_exponent, :rsa_modulus)
end

class KeyEcdsa < Struct.new("KeyEcdsa", :public_key_compX, :pulic_key_compY, :reserved)
end

class KeyEncryptedRsa < Struct.new("KeyEncryptedRsa", :encrypted_hash_rsa_public_exponent, :encrypted_hash_rsa_modulus)
end

class KeyEncryptedEcdsa < Struct.new("KeyEncryptedEcdsa", :encrypted_hash_public_key_compX_R, :encrypted_hash_public_key_compX_S, \
                                                          :encrypted_hash_public_key_compY_R, :encrypted_hash_public_key_compY_S, :reserved)
end

#PLAT_DS
class PlatDs < Struct.new("PlatDs", :ds_algorithm_id, :hash_algorithm_id, :key_size, :hash, :key)
end

class DsRsa < Struct.new("DsRsa", :rsa_public_exponent, :rsa_modulus, :rsa_digs)
end

class DsEcdsa < Struct.new("DsEcdsa", :ecdsa_public_key_compX, :ecdsa_public_key_compY, :ecdsa_digs_R, :ecdsa_digs_S, :reserved)
end

#RESERVED
class WtpReservedArea < Struct.new("WtpReservedArea", :wtptp_reserved_area_id, :num_reserved_packages)
end

class WtpReservedAreaHeader < Struct.new("WtpReservedAreaHeader", :identifier, :size)
end

class ReservedPackageValue < Struct.new("ReservedPackageValue", :wrah, :value)
end

class OptOemCust < ReservedPackageValue
end

class OptNoKeyDetect < ReservedPackageValue
end

class OPtNoFrequencyChange < ReservedPackageValue
end

class FuncConfig < ReservedPackageValue
end

class ProiT < Struct.new("ProiT", :wrah, :data)
end

class OptProtocolSet < Struct.new("OptProtocolSet", :wrah, :port, :enabled)
end

class ImageMap < Struct.new("ImageMap", :wrah, :num_of_mapped_images, :img_map_info)
end

class ImageMapInfo < Struct.new("ImageMapInfo", :image_id, :image_type, :flash_entry_addr, :partition_number)
end

class CidpPackage < Struct.new("CidpPackage", :wrah, :num_consumers, :consumers)
end

class CidpEntry < Struct.new("CidpEntry", :consumer_id, :num_packages_consume, :package_identifier_list)
end

class DdrPackage < Struct.new("DdrPackage", :wrah, :number_operations, :number_instructions, :ddr_operations, \
                                            :ddr_instructions)
end

class DdrOperation < Struct.new("DdrOperation", :op_id, :op_value)
end

class InstructionS < Struct.new("InstructionS", :instruction_id, :parameters)
end

class TimBuilder
  def initialize(base_url, layout_images, conf, release_dir)
    @base_url = base_url
    @layout_images = layout_images
    @conf = conf
    @release_dir = release_dir

    @timh_plat_ds = nil
    @dtim_plat_ds = nil
    @timh_rsa_private_key = nil
    @dtim_rsa_private_key = nil
    @timh_key_mods = []
    @dtim_key_mods = []
    @is_keys_loaded = false
  end

  #create all tims defined in layout_images
  def create_all_tims
    tim_types = []

    @layout_images.each do |image|
      if image['Id'] =~ /^TIM/
        tim_types << image['Tim']
      end
    end

    create_tims(tim_types)
  end

  #create tims according to tim included type array, for example: ['1', '4']
  def create_tims(tim_types)
    return if tim_types.nil? || tim_types.empty?

    image_maps = []
    tim_images_array = []

    @layout_images.each do |image|
      if tim_types.include?(image['Tim']) && image['Id'] =~ /^TIM/
        tim_images_array << [image]
      end
    end

    tim_images_array.each do |images|
      @layout_images.each do |image|
        if image['Tim'] == images[0]['Tim'] && image['Id'] != images[0]['Id'] && image['Type'] != 'RSV'
          images << image
        end
      end
    end

    @layout_images.each do |image|
      if image['Id'] =~ /^TIM/ && image['Id'] != 'TIMH'
        image_maps << image
      end
    end

    tim_images_array.each do |tim_images|
      is_timh = tim_images[0]['Id'] == 'TIMH'
      create_tim(tim_images, image_maps, is_timh)
    end
  end

  #just create boot rom timh
  def create_bootrom_tim(path)
    layout_images = Marshal.load(Marshal.dump(@layout_images))
    image_maps = []
    tim_images = []
    layout_images.each do |image|
      if image['Id'] == 'TIMH' && image['Tim'] == '1'
        image['Path'] = path
        tim_images[0] = image
      elsif image['Id'] == 'OBMI' && image['Tim'] == '1'
        image['Id'] = 'DKBI'
        image['MyId'] = "0x" + image['Id'].unpack('H*')[0].upcase
        tim_images[1] = image
      end

      if image['Id'] =~ /^TIM/ && image['Id'] != 'TIMH'
        image_maps << image
      end
    end

    create_tim(tim_images, image_maps, true)
  end

  #create one tim
  def create_tim(tim_images, image_maps, is_timh)
    return if tim_images.nil? || tim_images.empty?

    next_id_in_tim = "0xFFFFFFFF"
    tim_images.reverse_each do |image|
      image['NextIdInTim'] = next_id_in_tim
      next_id_in_tim = image['MyId']
    end

    tim_images.each do |image|
      if image['Id'] !~ /^TIM/ && image['Path'] != nil
        file_name = @release_dir + '/' + image['Path']
        if File.exist?(file_name)
          size = File.size(file_name)
          image['ActualSize'] = sprintf("0x%08X", size)
        else
          image['ActualSize'] = "0x00000000"
        end
      end
    end

    conf_tim_configuration = @conf['TIM_Configuration'][0]
    trusted = conf_tim_configuration['Trusted'].nil? ? 0 : conf_tim_configuration['Trusted'][0].to_i
    max_rsa_keysize_words = TimConsts::MAX_RSA_KEYSIZE_WORDS

    #load keys
    if trusted != 0 && !@is_keys_loaded
      load_plat_ds
      load_key_mods
      @is_keys_loaded = true
    end

    #create tim
    #CTIM
    c_tim = CTim.new
    version_i = VersionI.new(*([0]*5))
    version_i.version = conf_tim_configuration['Version'].nil? ? TimConsts::VERSION : conf_tim_configuration['Version'][0].hex
    version_i.identifier = TimConsts::TIM_ID
    version_i.trusted = trusted
    version_i.issue_date = conf_tim_configuration['Issue_Date'].nil? ? 0 : conf_tim_configuration['Issue_Date'][0].hex
    version_i.oem_unique_id = conf_tim_configuration['OEM_UniqueID'].nil? ? 0 : conf_tim_configuration['OEM_UniqueID'][0].hex

    flash_i = FlashI.new(*([0]*6))
    if trusted != 0
      flash_i.wtm_flash_sign = conf_tim_configuration['WTM_Save_State_Flash_Signature'].nil? ? 0 : conf_tim_configuration['WTM_Save_State_Flash_Signature'][0].hex
      flash_i.wtm_entry_addr = conf_tim_configuration['WTM_Save_State_Flash_Entry_Address'].nil? ? 0 : conf_tim_configuration['WTM_Save_State_Flash_Entry_Address'][0].hex
      flash_i.wtm_entry_addr_back = conf_tim_configuration['WTM_Save_State_BackUp_Entry_Address'].nil? ? 0 : conf_tim_configuration['WTM_Save_State_BackUp_Entry_Address'][0].hex
    else
      flash_i.wtm_flash_sign = 0x4D4D4308
      flash_i.wtm_entry_addr = 0
      flash_i.wtm_entry_addr_back = 0
    end
    flash_i.wtm_patch_sign = 0xFFFFFFFF
    flash_i.wtm_patch_addr = 0xFFFFFFFF
    flash_i.boot_flash_sign = conf_tim_configuration['Boot_Flash_Signature'].nil? ? 0 : conf_tim_configuration['Boot_Flash_Signature'][0].hex

    c_tim.version_bind = version_i
    c_tim.flash_info = flash_i
    c_tim.num_images = tim_images.size
    if trusted != 0
      if is_timh
        c_tim.num_keys = conf_tim_configuration['Number_of_Keys'].nil? ? 0 : conf_tim_configuration['Number_of_Keys'][0].to_i
      else
        c_tim.num_keys = 1
      end
    else
      c_tim.num_keys = 0
    end
    c_tim.size_of_reserved = 0

    #IMAGE_INFO_3_4_0
    image_infos = []
    tim_images.each do |image|
      image_info = ImageInfo_3_4_0.new(*([0]*7), [0]*16, 0)
      image_info.image_id = image['MyId'].hex
      image_info.next_image_id = image['NextIdInTim'].hex
      if image['Id'] == 'OBMI' || image['Id'] == 'DKBI'
        image_info.flash_entry_addr = image['FlashAddr'].hex & 0xFFFFFFFF
      else
        image_info.flash_entry_addr = (image['FlashAddr'].hex / 512) & 0xFFFFFFFF
      end
      image_info.load_addr = image['LoadAddr'].hex

      hash_algorithm_id = TimConsts::HASH_ALGORITHM_ID_T[image['HashAlgm']]
      image_info.hash_algorithm_id = hash_algorithm_id.nil? ? 0xFFFFFFFF : hash_algorithm_id

      if image['Id'] !~ /^TIM/
        image_info.image_size = image_info.image_size_to_hash = image['ActualSize'].hex
        if image['Path'] != nil && hash_algorithm_id != 0xFFFFFFFF
          file_name = @release_dir + '/' + image['Path']
          if File.exist?(file_name)
            hash_result = get_hash(File.binread(file_name, image_info.image_size_to_hash), image_info.hash_algorithm_id)
            image_info.hash[0, hash_result.size] = hash_result
          end
        end
      end

      image_info.partition_number = image['Part'].to_i

      image_infos << image_info
    end

    #KEY_MOD_3_4_0
    key_mods = []
    if trusted != 0
      if is_timh
        key_mods = @timh_key_mods
      else
        key_mods = @dtim_key_mods
      end
    end

    if key_mods.size != c_tim.num_keys
       raise "#{tim_images[0]['Id']}: key num does not match"
    end

    #RESERVED
    reserved = []
    if is_timh
      reserved = construct_reserved(image_maps)
    end

    #PLAT_DS
    plat_ds = nil
    if trusted != 0
      if is_timh
        plat_ds = @timh_plat_ds
        rsa_private_key = @timh_rsa_private_key
      else
        plat_ds = @dtim_plat_ds
        rsa_private_key = @dtim_rsa_private_key
      end
    end

    #TIM
    c_tim.size_of_reserved = (reserved.to_bytes).bytesize
    tim = Tim.new(c_tim, image_infos, key_mods, reserved, plat_ds)

    image_infos[0].image_size = (tim.to_bytes).bytesize
    if trusted != 0
      image_infos[0].image_size_to_hash = (tim.to_bytes).bytesize - max_rsa_keysize_words*4
    else
      image_infos[0].image_size_to_hash = (tim.to_bytes).bytesize
      if image_infos[0].hash_algorithm_id != 0xFFFFFFFF
        hash_result = get_hash(tim.to_bytes, image_infos[0].hash_algorithm_id)
        image_infos[0].hash[0, hash_result.size] = hash_result
      end
    end

    if trusted != 0
      ds = get_ds(tim.to_bytes[0, image_infos[0].image_size_to_hash], plat_ds.hash_algorithm_id, \
                  rsa_private_key)
      plat_ds.key.rsa_digs[0, ds.size] = ds
    end

    if tim_images[0]['Path'] != nil
      file_name = @release_dir + '/' + tim_images[0]['Path']
      puts "  #{file_name}"
      File.open(file_name, "wb:ASCII-8BIT") { |file| file.write(tim.to_bytes) }
    end
  end

  private

  def load_plat_ds
    max_rsa_keysize_words = TimConsts::MAX_RSA_KEYSIZE_WORDS
    ['TIMH', 'DTIM'].each do |id|
      if id == 'TIMH'
        ds_key = 'Digital_Signature_Data'
      elsif id == 'DTIM'
        ds_key = 'DTIM_Keys_Data'
      end

      conf_ds_data = @conf[ds_key][0]
      plat_ds = PlatDs.new

      algorithm_id = TimConsts::HASH_ALGORITHM_ID_T[conf_ds_data['Hash_Algorithm_ID'][0]]
      plat_ds.hash_algorithm_id = algorithm_id.nil? ? 0xFFFFFFFF : algorithm_id
      algorithm_id = TimConsts::ENCRYPT_ALGORITHM_ID_T[conf_ds_data['DSA_Algorithm'][0]]
      plat_ds.ds_algorithm_id = algorithm_id.nil? ? 0xFFFFFFFF : algorithm_id
      plat_ds.key_size = conf_ds_data['Key_Size_in_bits'][0].to_i
      plat_ds.hash = [0]*8

      ds_rsa = DsRsa.new([0]*max_rsa_keysize_words, [0]*max_rsa_keysize_words, [0]*max_rsa_keysize_words)
      conf_rsa_private_key_file = conf_ds_data['RSA_Private_Key'][0]
      url = "#{@base_url}/boardconf/SECURITY/#{conf_rsa_private_key_file}"
      rsa_private_key = get_content(url)
      rsa_key = RsaKey.new
      rsa_key.load(rsa_private_key)
      exponent_str = sprintf("%0#{plat_ds.key_size/4}X", rsa_key.get_key[1])
      exponent = ([exponent_str].pack('H*').force_encoding('ASCII-8BIT')).reverse.unpack('V*')
      ds_rsa.rsa_public_exponent[0, exponent.size] = exponent

      modulus_str = sprintf("%0#{plat_ds.key_size/4}X", rsa_key.get_key[0])
      modulus = ([modulus_str].pack('H*').force_encoding('ASCII-8BIT')).reverse.unpack('V*')
      ds_rsa.rsa_modulus[0, modulus.size] = modulus

      plat_ds.key = ds_rsa

      scheme = 0
      if plat_ds.ds_algorithm_id == TimConsts::ENCRYPT_ALGORITHM_ID_T['PKCS1_v1_5_Ippcp']
        if plat_ds.hash_algorithm_id == TimConsts::HASH_ALGORITHM_ID_T['SHA-160']
          scheme = plat_ds.key_size == 2048 ? TimConsts::PKCSv1_SHA1_2048RSA : TimConsts::PKCSv1_SHA1_1024RSA
        elsif plat_ds.hash_algorithm_id == TimConsts::HASH_ALGORITHM_ID_T['SHA-256']
          scheme = plat_ds.key_size == 2048 ? TimConsts::PKCSv1_SHA256_2048RSA : TimConsts::PKCSv1_SHA256_1024RSA
        end
      end
      raise "unsupported, check #{id} plat_ds's hash and ds algorithm" if scheme == 0

      data = scheme.to_bytes + (ds_rsa.rsa_modulus[0, plat_ds.key_size/8/4]).to_bytes + (ds_rsa.rsa_public_exponent[0, plat_ds.key_size/8/4]).to_bytes
      hash_result = get_hash(data, plat_ds.hash_algorithm_id)
      plat_ds.hash[0, hash_result.size] = hash_result

      if id == 'TIMH'
        @timh_plat_ds = plat_ds
        @timh_rsa_private_key = rsa_key
      elsif id == 'DTIM'
        @dtim_plat_ds = plat_ds
        @dtim_rsa_private_key = rsa_key
      end
    end
  end

  def load_key_mods
    max_rsa_keysize_words = TimConsts::MAX_RSA_KEYSIZE_WORDS
    #load timh's key mods
    conf_keys_data = @conf['Keys_Data'][0]
    conf_keys_data.each_value do |value|
      conf_key_data = value[0]
      key_mod = KeyMod_3_4_0.new
      key_mod.key_id = conf_key_data['KEY_Key_ID'][0].unpack('H*')[0].hex
      algorithm_id = TimConsts::HASH_ALGORITHM_ID_T[conf_key_data['KEY_Hash_Algorithm_ID'][0]]
      key_mod.hash_algorithm_id = algorithm_id.nil? ? 0xFFFFFFFF : algorithm_id
      algorithm_id = TimConsts::ENCRYPT_ALGORITHM_ID_T[conf_key_data['KEY_Encrypt_Algorithm_ID'][0]]
      key_mod.encrypt_algorithm_id = algorithm_id.nil? ? 0xFFFFFFFF : algorithm_id
      key_mod.key_size = conf_key_data['KEY_Key_Size_in_bits'][0].to_i
      key_mod.public_key_size  = conf_key_data['KEY_Public_Key_Size_in_bytes'][0].to_i

      key_rsa = KeyRsa.new([0]*max_rsa_keysize_words, [0]*max_rsa_keysize_words)

      conf_key_mod_file = conf_key_data['RSA_Public_Key'][0]
      url = "#{@base_url}/boardconf/SECURITY/#{conf_key_mod_file}"
      public_key = get_content(url)
      rsa_key = RsaKey.new
      rsa_key.load(public_key)
      exponent_str = sprintf("%0#{key_mod.key_size/4}X", rsa_key.get_key[1])
      exponent = ([exponent_str].pack('H*').force_encoding('ASCII-8BIT')).reverse.unpack('V*')
      key_rsa.rsa_public_exponent[0, exponent.size] = exponent

      modulus_str = sprintf("%0#{key_mod.key_size/4}X", rsa_key.get_key[0])
      modulus = ([modulus_str].pack('H*').force_encoding('ASCII-8BIT')).reverse.unpack('V*')
      key_rsa.rsa_modulus[0, modulus.size] = modulus
      key_mod.key = key_rsa

      key_mod.key_hash = [0]*16
      scheme = 0
      if key_mod.encrypt_algorithm_id == TimConsts::ENCRYPT_ALGORITHM_ID_T['PKCS1_v1_5_Ippcp']
        if key_mod.hash_algorithm_id == TimConsts::HASH_ALGORITHM_ID_T['SHA-160']
          scheme = key_mod.key_size == 2048 ? TimConsts::PKCSv1_SHA1_2048RSA : TimConsts::PKCSv1_SHA1_1024RSA
        elsif key_mod.hash_algorithm_id == TimConsts::HASH_ALGORITHM_ID_T['SHA-256']
          scheme = key_mod.key_size == 2048 ? TimConsts::PKCSv1_SHA256_2048RSA : TimConsts::PKCSv1_SHA256_1024RSA
        end
      end
      raise "unsupported, check timh key_mod's hash and ds algorithm" if scheme == 0

      data = scheme.to_bytes + (key_rsa.rsa_modulus[0, key_mod.key_size/8/4]).to_bytes + (key_rsa.rsa_public_exponent[0, key_mod.key_size/8/4]).to_bytes
      hash_result = get_hash(data, key_mod.hash_algorithm_id)
      key_mod.key_hash[0, hash_result.size] = hash_result

      @timh_key_mods << key_mod
    end

    #generate dtim's key mods
    key_mod = KeyMod_3_4_0.new
    key_mod.key_id = 'ENCK'.unpack('H*')[0].hex
    key_mod.hash_algorithm_id = @timh_plat_ds.hash_algorithm_id
    key_mod.encrypt_algorithm_id = @timh_plat_ds.ds_algorithm_id | 0x80000000
    key_mod.key_size = @timh_plat_ds.key_size
    key_mod.public_key_size = @dtim_plat_ds.key_size

    key_rsa = KeyEncryptedRsa.new([0]*max_rsa_keysize_words, [0]*max_rsa_keysize_words)
    ds = get_ds(@dtim_plat_ds.key.rsa_public_exponent[0, key_mod.public_key_size/8/4].to_bytes, key_mod.hash_algorithm_id, \
                @timh_rsa_private_key)
    key_rsa.encrypted_hash_rsa_public_exponent[0, ds.size] = ds
    ds = get_ds(@dtim_plat_ds.key.rsa_modulus[0, key_mod.public_key_size/8/4].to_bytes, key_mod.hash_algorithm_id, \
                @timh_rsa_private_key)
    key_rsa.encrypted_hash_rsa_modulus[0, ds.size] = ds
    key_mod.key = key_rsa

    key_mod.key_hash = [0]*16
    scheme = 0
    if key_mod.encrypt_algorithm_id & 0x7FFFFFFF == TimConsts::ENCRYPT_ALGORITHM_ID_T['PKCS1_v1_5_Ippcp']
      if key_mod.hash_algorithm_id == TimConsts::HASH_ALGORITHM_ID_T['SHA-160']
        scheme = key_mod.key_size == 2048 ? TimConsts::PKCSv1_SHA1_2048RSA : TimConsts::PKCSv1_SHA1_1024RSA
      elsif key_mod.hash_algorithm_id == TimConsts::HASH_ALGORITHM_ID_T['SHA-256']
        scheme = key_mod.key_size == 2048 ? TimConsts::PKCSv1_SHA256_2048RSA : TimConsts::PKCSv1_SHA256_1024RSA
      end
    end
    raise "unsupported, check dtim key_mod's hash and ds algorithm" if scheme == 0

    data = scheme.to_bytes + (key_rsa.encrypted_hash_rsa_modulus[0, key_mod.key_size/8/4]).to_bytes + (key_rsa.encrypted_hash_rsa_public_exponent[0, key_mod.key_size/8/4]).to_bytes
    hash_result = get_hash(data, key_mod.hash_algorithm_id)
    key_mod.key_hash[0, hash_result.size] = hash_result

    @dtim_key_mods << key_mod
  end

  def construct_reserved(image_maps)
    reserved = []
    conf_extended_reserved_data = @conf['Extended_Reserved_Data']
    conf_reserved_data = @conf['Reserved_Data']

    wtp_reserved_area = WtpReservedArea.new(0, 0)
    wtp_reserved_area.wtptp_reserved_area_id = TimConsts::WTP_RESERVED_AREA_ID
    wtp_reserved_area.num_reserved_packages = 0
    reserved << wtp_reserved_area

    #uart_id
    if conf_reserved_data != nil && conf_reserved_data[0]['UARTID'] != nil
      uart_port = conf_reserved_data[0]['UARTID'][0]['Port'][0].hex
      uart_enabled = conf_reserved_data[0]['UARTID'][0]['Enabled'][0].hex
      wrah = WtpReservedAreaHeader.new(0, 0)
      wrah.identifier = TimConsts::UART_ID
      uart = OptProtocolSet.new(wrah, uart_port, uart_enabled)
      wrah.size = (uart.to_bytes).bytesize
      reserved << uart
      pad_size = (wrah.size + 3) & ~3 - wrah.size
      reserved << PackagePadding.new(pad_size) if pad_size > 0
      wtp_reserved_area.num_reserved_packages += 1
    end

    #product_id
    if conf_reserved_data != nil && conf_reserved_data[0]['PROI'] != nil
      wrah = WtpReservedAreaHeader.new(0, 0)
      wrah.identifier = TimConsts::PRODUCT_ID
      product_id = conf_reserved_data[0]['PROI'][0]['PRODUCT_ID'][0].hex
      proi = ProiT.new(wrah, [product_id])
      wrah.size = (proi.to_bytes).bytesize
      reserved << proi
      pad_size = (wrah.size + 3) & ~3 - wrah.size
      reserved << PackagePadding.new(pad_size) if pad_size > 0
      wtp_reserved_area.num_reserved_packages += 1
    end

    #func_config
    if conf_reserved_data != nil && conf_reserved_data[0]['FCNF'] != nil
      wrah = WtpReservedAreaHeader.new(0, 0)
      wrah.identifier = TimConsts::FUNC_CONFIG_ID
      conf_func_config = conf_reserved_data[0]['FCNF'][0]['FUNC_CONFIG'][0].hex
      func_config = FuncConfig.new(wrah, conf_func_config)
      wrah.size = (func_config.to_bytes).bytesize
      reserved << func_config
      pad_size = (wrah.size + 3) & ~3 - wrah.size
      reserved << PackagePadding.new(pad_size) if pad_size > 0
      wtp_reserved_area.num_reserved_packages += 1
    end

    #cidp
    if conf_extended_reserved_data != nil && conf_extended_reserved_data[0]['Consumer_ID'] != nil
      cids = conf_extended_reserved_data[0]['Consumer_ID']
      wrah = WtpReservedAreaHeader.new(0, 0)
      wrah.identifier = TimConsts::CIDP_ID
      cidp_package = CidpPackage.new(wrah)
      consumers = []
      cids.each do |cid|
        next if cid.empty?
        cidp_entry = CidpEntry.new
        cidp_entry.consumer_id = cid['CID'][0].unpack('H*')[0].hex
        cidp_entry.num_packages_consume = cid['PID'].nil? ? 0 : cid['PID'].size
        cidp_entry.package_identifier_list = []
        if cid['PID'] != nil
          cid['PID'].each do |pid|
            cidp_entry.package_identifier_list << pid.unpack('H*')[0].hex
          end
        end
        consumers << cidp_entry if cidp_entry.package_identifier_list.size > 0
      end
      cidp_package.num_consumers = consumers.size
      cidp_package.consumers = consumers
      wrah.size = (cidp_package.to_bytes).bytesize
      if cidp_package.num_consumers > 0
        reserved << cidp_package
        pad_size = (wrah.size + 3) & ~3 - wrah.size
        reserved << PackagePadding.new(pad_size) if pad_size > 0
        wtp_reserved_area.num_reserved_packages += 1
      end
    end

    #ddr
    if conf_extended_reserved_data != nil && conf_extended_reserved_data[0]['DDR_Initialization'] != nil
      ddr_initializations = conf_extended_reserved_data[0]['DDR_Initialization']
      ddr_initializations.each do |ddr_initialization|
        next if ddr_initialization.empty?
        wrah = WtpReservedAreaHeader.new(0, 0)
        wrah.identifier = ddr_initialization['DDR_PID'][0].unpack('H*')[0].hex
        ddr_package = DdrPackage.new(wrah)
        ddr_operations = []
        if ddr_initialization['DDROperations'] != nil
          ddr_initialization['DDROperations'][0].each do |k, v|
            op_id = TimConsts::DDR_OPERATION[k]
            op_id = 0 if op_id.nil?
            op_value = v[0].hex
            ddr_operations << DdrOperation.new(op_id, op_value)
          end
        end
        ddr_package.number_operations = ddr_operations.size
        ddr_package.ddr_operations = ddr_operations

        ddr_instructions = []
        if ddr_initialization['Instructions'] != nil
          table_header = []
          ddr_initialization['Instructions'][0].each do |k, v|
            case k
              when /^WRITE/
                ins = InstructionS.new
                ins.instruction_id = 1
                parms = (v[0].delete(' ')[1..-2]).split(',')
                parms.map! {|x| x.hex}
                ins.parameters = parms
                ddr_instructions << ins
              when /^WAIT_FOR_BIT_SET/
                ins = InstructionS.new
                ins.instruction_id = 4
                parms = (v[0].delete(' ')[1..-2]).split(',')
                parms.map! {|x| x.hex}
                ins.parameters = parms
                ddr_instructions << ins
              when /^PP_TABLEHEADER/
                table_header = (v[0].delete(' ')[1..-2]).split(',')
                table_header.map! {|x| x.hex}
              when /^PP_WRITE/
                parms = (v[0].delete(' ')[1..-2]).split(',')
                parms.map! {|x| x.hex}
                table_header.each_with_index do |x, i|
                  ins = InstructionS.new
                  ins.instruction_id = 1
                  ins.parameters = [x, parms[i]]
                  ddr_instructions << ins
                end
            end
          end
        end
        ddr_package.number_instructions = ddr_instructions.size
        ddr_package.ddr_instructions = ddr_instructions

        wrah.size = (ddr_package.to_bytes).bytesize
        reserved << ddr_package
        pad_size = (wrah.size + 3) & ~3 - wrah.size
        reserved << PackagePadding.new(pad_size) if pad_size > 0

        wtp_reserved_area.num_reserved_packages += 1
      end
    end

    #imap
    if image_maps != nil && !image_maps.empty?
      wrah = WtpReservedAreaHeader.new(0, 0)
      wrah.identifier = TimConsts::IMAP_ID
      imap = ImageMap.new(wrah, image_maps.size)
      image_map_infos = []
      image_maps.each do |image|
        image_map_info = ImageMapInfo.new
        image_map_info.image_id = image['MyId'].hex
        image_map_info.image_type = TimConsts::DTIM_IMAGE_TYPE[image['Type']]
        flash_addr = image['FlashAddr'].hex
        image_map_info.flash_entry_addr =[(flash_addr / 512) & 0xFFFFFFFF, 0]
        image_map_info.partition_number = image['Part'].to_i
        image_map_infos << image_map_info
      end
      imap.img_map_info = image_map_infos

      wrah.size = (imap.to_bytes).bytesize
      reserved << imap
      pad_size = (wrah.size + 3) & ~3 - wrah.size
      reserved << PackagePadding.new(pad_size) if pad_size > 0

      wtp_reserved_area.num_reserved_packages += 1
    end

    #terminator
    wrah = WtpReservedAreaHeader.new(TimConsts::TERMINATOR_ID, 8)
    reserved << wrah
    wtp_reserved_area.num_reserved_packages += 1

    reserved = [] if wtp_reserved_area.num_reserved_packages <= 1
    return reserved
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
    ds = private_key.sign(sha_name, data).force_encoding('ASCII-8BIT')
    return (ds.reverse).unpack('V*')
  end

  def get_content(url)
    if url.start_with?('http://', 'https://')
      return Net::HTTP.get_response(URI.parse(url)).body
    else
      return `cat #{url}`
    end
  end
end

