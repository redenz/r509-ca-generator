require 'r509'
require 'dependo'
require 'logger'
require 'json'

Dependo::Registry[:log] = Logger.new(STDOUT)


config_data = YAML.load_file('config.yaml')

config_data['certificate_authorities'].each do |key, config|
  
  ca_cert = config['ca_cert']
  cert_file = ca_cert["cert"]
  key_file = ca_cert["cert"].sub(".pem", ".key")
  not_before = Time.now.to_i
  not_after = Time.now.to_i+3600*24*7300
  csr = R509::CSR.new(
      :subject => [['C','US'],['O','r509 LLC'],['CN',key]]
  )
  ca = R509::CertificateAuthority::Signer.new
  cert = ca.selfsign(
      :csr => csr,
      :not_before => not_before,
      :not_after => not_after
  )

  if config.has_key?('crl_list')
    File.open(config['crl_list'], 'w') {}
  end

  if config.has_key?('crl_number')
    File.open(config['crl_number'], 'w') {}
  end

  cert.write_pem(cert_file)
  csr.key.write_pem(key_file)
end
