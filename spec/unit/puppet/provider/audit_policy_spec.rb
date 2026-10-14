# frozen_string_literal: true

require 'spec_helper'

provider_resource = Puppet::Type.type(:audit_policy)
provider_class    = provider_resource.provider(:auditpol)

# Output of `auditpol /backup` on a zh-TW host: subcategory names and inclusion
# settings are localized, GUIDs and setting values are not.
BACKUP_HEADER = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n"
LOCALIZED_BACKUP = "#{BACKUP_HEADER}TLT0117,系統,登入,{0CCE9215-69AE-11D9-BED3-505054503030},失敗,,2\r\n" \
                   "TLT0117,系統,認證驗證,{0CCE923F-69AE-11D9-BED3-505054503030},成功與失敗,,3\r\n" \
                   "TLT0117,系統,登出,{0CCE9216-69AE-11D9-BED3-505054503030},成功,,1\r\n" \
                   "TLT0117,系統,帳戶鎖定,{0CCE9217-69AE-11D9-BED3-505054503030},沒有稽核,,0\r\n" \
                   "TLT0117,S-1-5-21-1-2-3-1001,登入,{0CCE9215-69AE-11D9-BED3-505054503030},成功與失敗,,3\r\n" \
                   "TLT0117,,Option:CrashOnAuditFail,,Disabled,,0\r\n" \
                   "TLT0117,,RegistryGlobalSacl,,,,\r\n"

def utf16le_with_bom(str)
  "\xFF\xFE".b + str.encode(Encoding::UTF_16LE).b
end

describe provider_class do
  context 'when running on Windows', if: RUBY_PLATFORM =~ %r{cygwin|mswin|mingw|bccwin|wince|emx} do
    subject { provider_class }

    let(:resource) do
      provider_resource.new(
        subcategory: 'Logon',
        success: :enable,
        failure: :disable,
      )
    end

    let(:provider) { described_class.new(resource) }

    describe 'provider' do
      it 'will be an instance of Puppet::Type::audit_policy::auditpol' do
        expect(provider).to be_an_instance_of Puppet::Type::Audit_policy::ProviderAuditpol
      end

      it 'will respond to function calls' do
        expect(provider).to respond_to(:success)
        expect(provider).to respond_to(:failure)
        expect(provider).to respond_to(:guid)
        expect(provider).to respond_to(:flush)
        expect(provider.class).to respond_to(:instances)
        expect(provider.class).to respond_to(:prefetch)
      end

      describe 'instances' do
        it 'will return policy properties' do
          allow(provider.class).to receive(:read_backup).and_return(utf16le_with_bom(LOCALIZED_BACKUP))
          expect(provider.class).to respond_to(:instances)
        end
      end

      describe 'flush' do
        it 'will try and call auditpol in order to set auditing policies' do
          allow(provider.class).to receive(:audit_policy)
          expect(provider).to receive(:auditpol).with(['/set', '/subcategory:Logon'])
          provider.flush
        end
      end

      describe 'self.' do
        let(:provider) do
          described_class.new
        end

        describe 'prefetch' do
          context 'with valid resource' do
            it 'will store prov into resource.provider' do
              prov_mock = instance_double('Provider', name: 'foo')
              resource_mock = instance_double('Resource')
              allow(resource_mock).to receive(:[]).with(:guid).and_return(nil)
              expect(resource_mock).to receive(:provider=)
              resources = {}
              resources['foo'] = resource_mock
              allow(provider.class).to receive(:instances).and_return([prov_mock])
              provider.class.prefetch(resources)
            end
          end
        end
      end
    end
  end

  # The behaviour below does not shell out to auditpol.exe, so it is tested on
  # every platform.
  context 'without auditpol.exe' do
    let(:resource) do
      provider_resource.new(
        subcategory: 'Logon',
        success: :enable,
        failure: :disable,
      )
    end

    let(:guid_resource) do
      provider_resource.new(
        subcategory: 'Logon',
        guid: '{0CCE9215-69AE-11D9-BED3-505054503030}',
        success: :enable,
        failure: :disable,
      )
    end

    describe 'parse_backup' do
      it 'parses UTF-16LE output with a byte order mark' do
        policies = described_class.parse_backup(utf16le_with_bom(LOCALIZED_BACKUP))
        expect(policies).to eq(
          [
            { name: '登入', guid: '{0cce9215-69ae-11d9-bed3-505054503030}', success: 'disable', failure: 'enable' },
            { name: '認證驗證', guid: '{0cce923f-69ae-11d9-bed3-505054503030}', success: 'enable', failure: 'enable' },
            { name: '登出', guid: '{0cce9216-69ae-11d9-bed3-505054503030}', success: 'enable', failure: 'disable' },
            { name: '帳戶鎖定', guid: '{0cce9217-69ae-11d9-bed3-505054503030}', success: 'disable', failure: 'disable' },
          ],
        )
      end

      it 'parses UTF-8 output with a byte order mark' do
        policies = described_class.parse_backup("\xEF\xBB\xBF".b + LOCALIZED_BACKUP.b)
        expect(policies.map { |p| p[:guid] }).to eq(
          [
            '{0cce9215-69ae-11d9-bed3-505054503030}',
            '{0cce923f-69ae-11d9-bed3-505054503030}',
            '{0cce9216-69ae-11d9-bed3-505054503030}',
            '{0cce9217-69ae-11d9-bed3-505054503030}',
          ],
        )
      end

      it 'parses output in a legacy code page' do
        legacy = "#{BACKUP_HEADER}TLT0117,系統,登入,{0CCE9215-69AE-11D9-BED3-505054503030},失敗,,2\r\n".encode('CP950')
        policies = described_class.parse_backup(legacy.b)
        expect(policies.length).to eq(1)
        expect(policies[0]).to include(guid: '{0cce9215-69ae-11d9-bed3-505054503030}', success: 'disable', failure: 'enable')
      end

      it 'keeps the system policy when a per-user policy has the same GUID' do
        policies = described_class.parse_backup(LOCALIZED_BACKUP)
        logon = policies.select { |p| p[:guid] == '{0cce9215-69ae-11d9-bed3-505054503030}' }
        expect(logon).to eq([{ name: '登入', guid: '{0cce9215-69ae-11d9-bed3-505054503030}', success: 'disable', failure: 'enable' }])
      end

      it 'ignores a per-user row that precedes the system row' do
        backup = "#{BACKUP_HEADER}PC,S-1-5-21-1-2-3-1001,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3\r\n" \
                 "PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Failure,,2\r\n"
        expect(described_class.parse_backup(backup)).to eq([{ name: 'Logon', guid: '{0cce9215-69ae-11d9-bed3-505054503030}', success: 'disable', failure: 'enable' }])
      end

      it 'keeps the full name when a localized subcategory name contains a comma' do
        backup = "#{BACKUP_HEADER}TLT0117,System,Logon, Logoff,{0CCE9215-69AE-11D9-BED3-505054503030},Success,,1\r\n"
        expect(described_class.parse_backup(backup)).to eq([{ name: 'Logon, Logoff', guid: '{0cce9215-69ae-11d9-bed3-505054503030}', success: 'enable', failure: 'disable' }])
      end

      it 'skips rows with an unknown setting value' do
        allow(Puppet).to receive(:warning)
        backup = "#{BACKUP_HEADER}TLT0117,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,,9\r\n"
        expect(described_class.parse_backup(backup)).to eq([])
      end

      it 'warns when data rows are present but none can be parsed' do
        expect(Puppet).to receive(:warning).with(%r{no subcategory rows could be parsed})
        bomless_utf16 = "#{BACKUP_HEADER}PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,,1\r\n".encode(Encoding::UTF_16LE).b
        expect(described_class.parse_backup(bomless_utf16)).to eq([])
      end

      it 'returns nothing for a header-only file without warning' do
        expect(Puppet).not_to receive(:warning)
        expect(described_class.parse_backup(BACKUP_HEADER)).to eq([])
      end
    end

    describe 'read_backup' do
      it 'calls auditpol /backup with a Windows path and returns the file contents' do
        allow(Dir).to receive(:mktmpdir).with('audit_policy').and_yield('C:/tmp/ap')
        expect(described_class).to receive(:auditpol).with('/backup', '/file:C:\\tmp\\ap\\auditpol_backup.csv')
        allow(File).to receive(:binread).with('C:/tmp/ap/auditpol_backup.csv').and_return('contents')
        expect(described_class.read_backup).to eq('contents')
      end
    end

    describe 'instances' do
      it 'returns one provider per system subcategory' do
        allow(described_class).to receive(:read_backup).and_return(utf16le_with_bom(LOCALIZED_BACKUP))
        instances = described_class.instances
        expect(instances.map(&:guid)).to eq(
          [
            '{0cce9215-69ae-11d9-bed3-505054503030}',
            '{0cce923f-69ae-11d9-bed3-505054503030}',
            '{0cce9216-69ae-11d9-bed3-505054503030}',
            '{0cce9217-69ae-11d9-bed3-505054503030}',
          ],
        )
        expect(instances.map(&:name)).to eq(%w[登入 認證驗證 登出 帳戶鎖定])
      end
    end

    describe 'flush' do
      it 'uses the name when no GUID is set' do
        provider = described_class.new(resource)
        provider.instance_variable_set(:@property_flush, success: :enable, failure: :disable)
        expect(provider).to receive(:auditpol).with(['/set', '/subcategory:Logon', '/success:enable', '/failure:disable'])
        provider.flush
      end

      it 'uses the GUID instead of the name when one is set' do
        provider = described_class.new(guid_resource)
        provider.instance_variable_set(:@property_flush, success: :enable, failure: :disable)
        expect(provider).to receive(:auditpol).with(['/set', '/subcategory:{0cce9215-69ae-11d9-bed3-505054503030}', '/success:enable', '/failure:disable'])
        provider.flush
      end

      it 'only passes the properties that changed' do
        provider = described_class.new(guid_resource)
        provider.instance_variable_set(:@property_flush, failure: :disable)
        expect(provider).to receive(:auditpol).with(['/set', '/subcategory:{0cce9215-69ae-11d9-bed3-505054503030}', '/failure:disable'])
        provider.flush
      end
    end

    describe 'prefetch' do
      it 'matches a localized policy by GUID' do
        allow(described_class).to receive(:read_backup).and_return(utf16le_with_bom(LOCALIZED_BACKUP))
        described_class.prefetch('Logon' => guid_resource)
        expect(guid_resource.provider.guid).to eq('{0cce9215-69ae-11d9-bed3-505054503030}')
        expect(guid_resource.provider.success).to eq('disable')
        expect(guid_resource.provider.failure).to eq('enable')
      end

      it 'does not match a localized policy by English name' do
        allow(described_class).to receive(:read_backup).and_return(utf16le_with_bom(LOCALIZED_BACKUP))
        original = resource.provider
        described_class.prefetch('Logon' => resource)
        expect(resource.provider).to equal(original)
      end
    end
  end
end
