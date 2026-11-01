#!/usr/bin/env python3
"""Synthetic multi-profile Zsign verification. No Apple calls or Keychain imports."""
import datetime, json, pathlib, plistlib, subprocess, tempfile, sys, struct, hashlib
repo = pathlib.Path(__file__).resolve().parents[2]
framework = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path('/tmp/isign-feather-build/SourcePackages/checkouts/OpenSSL/Frameworks/OpenSSL.xcframework/macos-arm64_x86_64')
def run(*args):
    result = subprocess.run([str(a) for a in args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace') + result.stdout.decode(errors='replace'))
with tempfile.TemporaryDirectory(prefix='isign-client-bridge-') as directory:
    root = pathlib.Path(directory)
    sources = ['archo.cpp', 'bundle.cpp', 'macho.cpp', 'openssl.cpp', 'signing.cpp'] + ['common/' + name + '.cpp' for name in ['base64', 'fs', 'json', 'log', 'sha', 'timer', 'util']]
    run('xcrun', 'clang++', '-std=c++17', '-fobjc-arc', '-I'+str(repo/'Zsign/src'), '-I'+str(repo/'Zsign/src/common'), '-F'+str(framework), '-framework', 'OpenSSL', '-framework', 'Foundation', '-Wl,-rpath,'+str(framework), repo/'Tests/SigningBridgeSmoke/main.mm', repo/'ISignClient/iSign/ISignZsignBridge.mm', *[repo/'Zsign/src'/s for s in sources], '-o', root/'bridge')
    run('/usr/bin/openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', root/'key.pem', '-out', root/'cert.pem', '-subj', '/CN=iSign Client Synthetic Test', '-days', '1')
    run('/usr/bin/openssl', 'pkcs12', '-export', '-inkey', root/'key.pem', '-in', root/'cert.pem', '-out', root/'unsupported.p12', '-password', 'pass:test-only', '-keypbe', 'AES-256-CBC', '-certpbe', 'AES-256-CBC')
    # Zsign selects its CMS chain by issuer-name hash. This LOCAL fake CA mirrors
    # that name only; its key is random and it does not create Apple-trusted assets.
    run('/usr/bin/openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', root/'ca-key.pem', '-out', root/'ca.pem', '-subj', '/CN=Apple Worldwide Developer Relations Certification Authority/OU=G3/O=Apple Inc./C=US', '-days', '1')
    run('/usr/bin/openssl', 'req', '-new', '-key', root/'key.pem', '-out', root/'leaf.csr', '-subj', '/CN=iSign Client Synthetic Test/OU=TEAM123456/O=Fixture')
    run('/usr/bin/openssl', 'x509', '-req', '-in', root/'leaf.csr', '-CA', root/'ca.pem', '-CAkey', root/'ca-key.pem', '-CAcreateserial', '-days', '1', '-out', root/'cert.pem')
    run('/usr/bin/openssl', 'x509', '-in', root/'cert.pem', '-outform', 'DER', '-out', root/'cert.der')
    run('/usr/bin/openssl', 'pkcs12', '-export', '-inkey', root/'key.pem', '-in', root/'cert.pem', '-out', root/'fixture.p12', '-password', 'pass:test-only', '-keypbe', 'AES-256-CBC', '-certpbe', 'AES-256-CBC')
    (root/'main.c').write_text('int main(void) { return 0; }\n')
    assets = []
    targets = [(root/'Fixture.app', 'org.fixture.app', 'Root'), (root/'Fixture.app/PlugIns/Widget.appex', 'org.fixture.app.widget', 'Widget')]
    for index, (target, bundle, executable) in enumerate(targets):
        target.mkdir(parents=True)
        (target/'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':bundle, 'CFBundleExecutable':executable, 'CFBundleName':executable, 'CFBundleVersion':'1', 'CFBundleShortVersionString':'1.0', 'CFBundlePackageType':'APPL' if index == 0 else 'XPC!'}))
        run('xcrun', '--sdk', 'iphoneos', 'clang', '-target', 'arm64-apple-ios16.0', root/'main.c', '-o', target/executable)
        entitlements = {'application-identifier':'TEAM123456.'+bundle, 'com.apple.developer.team-identifier':'TEAM123456', 'get-task-allow':False}
        profile = {'UUID':'fixture-'+str(index), 'Name':'Fixture '+str(index), 'TeamIdentifier':['TEAM123456'], 'ExpirationDate':datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)+datetime.timedelta(days=1), 'DeveloperCertificates':[(root/'cert.der').read_bytes()], 'ProvisionedDevices':['synthetic-device'], 'Entitlements':entitlements}
        source = root/f'{index}.plist'; source.write_bytes(plistlib.dumps(profile))
        cms = root/f'{index}.mobileprovision'
        run('/usr/bin/openssl', 'cms', '-sign', '-binary', '-nodetach', '-in', source, '-signer', root/'cert.pem', '-inkey', root/'key.pem', '-outform', 'DER', '-out', cms)
        entitlement_file = root/f'{index}.entitlements'; entitlement_file.write_bytes(plistlib.dumps(entitlements))
        assets.append({'target':str(target), 'profile':str(cms), 'entitlements':str(entitlement_file), 'team':'TEAM123456', 'bundleId':bundle})
    (root/'assets.json').write_text(json.dumps(assets))
    supported = (root/'fixture.p12').read_bytes()
    (root/'fixture.p12').write_bytes((root/'unsupported.p12').read_bytes())
    rejected = subprocess.run([str(root/'bridge'), str(root), 'preserve'], capture_output=True)
    assert rejected.returncode == 3, 'Unknown issuer was accepted'
    assert not (targets[0][0]/'embedded.mobileprovision').exists()
    (root/'fixture.p12').write_bytes(supported)
    print('Unsupported issuer rejected before app mutation')
    for mode in ['preserve', 'remove']:
        run(root/'bridge', root, mode)
        for target, bundle, executable in targets:
            assert (target/'embedded.mobileprovision').exists() == (mode == 'preserve')
            data = (target/executable).read_bytes()
            position = 32; slots = {}
            assert data[:4] == bytes.fromhex('cffaedfe')
            for _ in range(struct.unpack_from('<I', data, 16)[0]):
                command, size = struct.unpack_from('<II', data, position)
                if command == 0x1d:
                    offset, length = struct.unpack_from('<II', data, position+8)
                    magic, blobsize, count = struct.unpack_from('>III', data, offset)
                    assert magic == 0xfade0cc0 and blobsize <= length
                    for index in range(count):
                        kind, blob = struct.unpack_from('>II', data, offset+12+index*8)
                        blobmagic, size = struct.unpack_from('>II', data, offset+blob)
                        slots[kind] = data[offset+blob:offset+blob+size]
                position += struct.unpack_from('<I', data, position+4)[0]
            actual = plistlib.loads(slots[5][8:])
            assert actual['application-identifier'] == 'TEAM123456.'+bundle, actual
            for kind, algorithm in [(0, hashlib.sha1), (4096, hashlib.sha256)]:
                cd = slots[kind]
                hash_offset = struct.unpack_from('>I', cd, 16)[0]
                hash_size, page_size = cd[36], 2**cd[39]
                pages, code_limit = struct.unpack_from('>II', cd, 28)
                assert cd[hash_offset-5*hash_size:hash_offset-4*hash_size] == algorithm(slots[5]).digest()
                for page in range(pages):
                    expected = algorithm(data[page*page_size:min((page+1)*page_size, code_limit)]).digest()
                    assert cd[hash_offset+page*hash_size:hash_offset+(page+1)*hash_size] == expected
            (root/'cms.der').write_bytes(slots[65536][8:]); (root/'codedirectory').write_bytes(slots[0])
            run('/usr/bin/openssl', 'cms', '-verify', '-binary', '-inform', 'DER', '-in', root/'cms.der', '-content', root/'codedirectory', '-noverify', '-out', root/'verified')
        print(f'{mode}: correct root/extension profiles, entitlements, code hashes and CMS signatures')
    # Capture the stock-engine host inspector limitation separately from our checks.
    inspector = ['/usr/bin/codesign', '-d', '--entitlements', '-', '--xml', str(targets[0][0]/targets[0][2])]
    managed = subprocess.run(inspector, capture_output=True)
    run(root/'bridge', root, 'stock')
    stock = subprocess.run(inspector, capture_output=True)
    warning = b'invalid entitlements blob'
    if warning in managed.stderr:
        assert warning in stock.stderr, 'Managed adapter introduced an inspector warning absent from stock Zsign'
        print('Host codesign entitlement warning also reproduced with unchanged stock single-profile Zsign; physical-device validation still required.')
