"""Deterministic reviewable strict-plan patch for upstream zsign v1.1.2."""

import hashlib, pathlib, shutil

UPSTREAM_COMMIT = "614caa8d1ca949e260e5746144aa52d27a4b08d6"
SOURCE_MANIFEST_SHA256 = "4ca64a1fa2fc6bf4e953909239b1e1bc99707b8a541584cc27d52a720a6780f8"
PINS = {
    "src/common/sha.cpp": "396b092f29d16e9af00f4567ac3680e34a7ae922e3e98feba7c96010d00f7f02",
    "build/linux/Makefile": "27acd9444696545a0d4ead95050f0fbbd5e990f31a2f6361e6fa2ef40d84687d",
    "build/macos/Makefile": "3313376f9c62a5bc5e064c60abdfb3d693c0b5e626c1a1c2e0378ccafb613ead",
    "src/bundle.cpp": "9c488f55098c52aa2599c75452ff957264a5cfa282021edbe5bd8b9a3101ad55",
    "src/bundle.h": "101b73ccaa081ca906ced33fe7ed8c630fd5e96e8ee056e0d19e5a75decf3a73",
    "src/zsign.cpp": "64922369263bcb10ff715dde702879cd3dad192a7a07932d9e336ea22fc97e08",
    "src/signing.cpp": "adec8f5af9fac63aebacdc9f6d5924ee384e3d7c48473e7bcbe4638b8d860d91",
    "src/archo.cpp": "6fb8e87d80a314385c787302421fc9861dca160326f1815996d27bc77251f43e",
}


def patch(source, destination):
    source = pathlib.Path(source)
    destination = pathlib.Path(destination)
    if destination.exists():
        raise ValueError("PATCH_DESTINATION_EXISTS")
    for path, digest in PINS.items():
        if hashlib.sha256((source / path).read_bytes()).hexdigest() != digest:
            raise ValueError("ZSIGN_SOURCE_PIN_MISMATCH")
    files = sorted(path for path in (source / "src").rglob("*") if path.is_file())
    if any(path.is_symlink() for path in (source / "src").rglob("*")):
        raise ValueError("ZSIGN_SOURCE_SYMLINK_REJECTED")
    manifest = "".join(
        str(path.relative_to(source)) + "\0" + hashlib.sha256(path.read_bytes()).hexdigest() + "\n"
        for path in files
    )
    if hashlib.sha256(manifest.encode()).hexdigest() != SOURCE_MANIFEST_SHA256:
        raise ValueError("ZSIGN_FULL_SOURCE_PIN_MISMATCH")
    destination.mkdir()
    shutil.copytree(source / "src", destination / "src")
    (destination / "build/linux").mkdir(parents=True)
    (destination / "build/macos").mkdir(parents=True)
    for platform in ("linux", "macos"):
        shutil.copyfile(
            source / ("build/" + platform + "/Makefile"),
            destination / ("build/" + platform + "/Makefile"),
        )
    if (source / "LICENSE").is_file():
        shutil.copyfile(source / "LICENSE", destination / "LICENSE")
    signing = destination / "src/signing.cpp"
    text = signing.read_text()
    begin = text.index("\t} else if (data.is_int()) {")
    end = text.index("\t} else if (data.is_string()) {", begin)
    text = (
        text[:begin]
        + r"""
	} else if (data.is_int()) {
		uint64_t bits = static_cast<uint64_t>(data.as_int64());
		string integer;
		for (int shift = 56; shift >= 0; shift -= 8) {
			integer.append(1, static_cast<char>(bits >> shift));
		}
		while (integer.size() > 1) {
			unsigned char first = static_cast<unsigned char>(integer[0]);
			unsigned char next = static_cast<unsigned char>(integer[1]);
			if ((first == 0 && next < 128) || (first == 255 && next >= 128)) {
				integer.erase(0, 1);
			} else {
				break;
			}
		}
		strOutput.append(1, 0x02);
		_DERLength(strOutput, integer.size());
		strOutput += integer;
"""
        + text[end:]
    )
    signing.write_text(text)
    # Re-signing can shrink the superblob while LC_CODE_SIGNATURE retains its
    # allocation. Clear the previous signature's remainder after replacing it.
    archo = destination / "src/archo.cpp"
    text = archo.read_text()
    begin = text.index("\tint nSpaceLength =", text.index("bool ZArchO::Sign("))
    end = text.index("\treturn true;\n}", begin)
    text = (
        text[:begin]
        + r"""
	if (m_uCodeLength > m_uLength ||
		strCodeSignBlob.size() > static_cast<size_t>(m_uLength - m_uCodeLength)) {
		m_bEnoughSpace = false;
		ZLog::Warn(">>> Insufficient CodeSignature space.\n");
		return false;
	}
	const size_t nSpaceLength = static_cast<size_t>(m_uLength - m_uCodeLength) - strCodeSignBlob.size();
	memcpy(m_pBase + m_uCodeLength, strCodeSignBlob.data(), strCodeSignBlob.size());
	memset(m_pBase + m_uCodeLength + strCodeSignBlob.size(), 0, nSpaceLength);
"""
        + text[end:]
    )
    archo.write_text(text)
    header = destination / "src/bundle.h"
    text = header.read_text().replace(
        "public:\n\tZBundle();", "public:\n\tZBundle();\n\tstring m_strIsignPlan;"
    )
    header.write_text(text)
    cli = destination / "src/zsign.cpp"
    text = (
        cli.read_text()
        .replace(
            '{"debug", no_argument',
            '{"isign-plan", required_argument, NULL, \'J\'},\n\t{"isign-password-stdin", no_argument, NULL, \'K\'},\n\t{"debug", no_argument',
        )
        .replace("string strCertFile;", "string strIsignPlan;\n\tstring strCertFile;")
        .replace("dfva2LhiqwCRSEWUPc:", "dfva2LhiqwCRSEWUPKJ:c:")
        .replace(
            "case 'd':",
            "case 'K': { char pass[1026]; if (!fgets(pass, sizeof(pass), stdin)) return -1; string secret(pass); if (secret.empty() || secret.back() != '\\n' || secret.size() > 1025) return -1; secret.pop_back(); if (secret.empty() || secret.find('\\r') != string::npos) return -1; strPassword = secret; break; }\n\t\tcase 'J': strIsignPlan = ZFile::GetFullPath(optarg); break;\n\t\tcase 'd':",
        )
        .replace(
            "ZBundle bundle;",
            "if (strIsignPlan.empty() || !strEntitleFile.empty() || arrProvFiles.empty()) { return -1; }\n\tZBundle bundle;\n\tbundle.m_strIsignPlan = strIsignPlan;",
        )
    )
    cli.write_text(text)
    cpp = destination / "src/bundle.cpp"
    text = cpp.read_text()
    loose_begin = text.index('\tif (jvNode.has("files")) {', text.index("bool ZBundle::SignNode("))
    loose_end = text.index('\n\tif (jvNode.has("folders")) {', loose_begin)
    text = (
        text[:loose_begin]
        + r"""
	jvalue filePlan;
	if (m_strIsignPlan.empty() || !filePlan.read_from_file(m_strIsignPlan.c_str()) || !filePlan.is_object()) return false;
	set<string> bundleExecutables;
	set<string> discovered;
	if (jvNode["path"].as_string() == "/") {
		discovered.insert("/");
		bundleExecutables.insert(jvNode["bundle_executable"].as_string());
		for (size_t i = 0; i < jvNode["folders"].size(); ++i) {
			jvalue folder = jvNode["folders"][i];
			string path = folder["path"];
			if (!filePlan.has(path) || filePlan[path]["kind"].as_string() == "dylib") return false;
			discovered.insert(path);
			bundleExecutables.insert(path + "/" + folder["bundle_executable"].as_string());
		}
		for (size_t i = 0; i < jvNode["files"].size(); ++i) {
			string path = jvNode["files"][i];
			if (bundleExecutables.count(path)) continue;
			if (!filePlan.has(path) || filePlan[path]["kind"].as_string() != "dylib" || !ZFile::IsPathSuffix(path, ".dylib")) return false;
			discovered.insert(path);
		}
		vector<string> planned;
		if (!filePlan.get_keys(planned) || set<string>(planned.begin(), planned.end()) != discovered) return false;
	}
	if (jvNode.has("files")) {
		for (size_t i = 0; i < jvNode["files"].size(); ++i) {
			string strFile = jvNode["files"][i];
			if (bundleExecutables.count(strFile)) continue;
			if (!filePlan.has(strFile)) return false;
			jvalue node = filePlan[strFile];
			if (node["kind"].as_string() != "dylib" || !ZFile::IsPathSuffix(strFile, ".dylib")) return false;
			string fullPath = m_strAppFolder + "/" + strFile;
			FILE* input = fopen(fullPath.c_str(), "rb");
			if (!input) return false;
			uint32_t header[4];
			bool supported = fread(header, sizeof(header), 1, input) == 1 && header[0] == MH_MAGIC_64 && header[1] == 0x100000c && header[3] == MH_DYLIB;
			fclose(input);
			if (!supported) return false;
			string digest;
			if (!ZSHA::SHA256(string("Payload/") + ZUtil::GetBaseName(m_strAppFolder.c_str()) + "/" + strFile, digest)) return false;
			string identifier = "isign.dylib.";
			for (unsigned char byte : digest) { char hex[3]; snprintf(hex, sizeof(hex), "%02x", byte); identifier += hex; }
			if (node["bundleId"].as_string() != identifier) return false;
			string applicationId = node["applicationId"];
			ZSignAsset* selected = NULL;
			if (m_pSignAssets) {
				for (auto &asset : *m_pSignAssets) { if (asset.m_strApplicationId == applicationId) { if (selected) return false; selected = &asset; } }
			} else if (m_pSignAsset->m_strApplicationId == applicationId) { selected = m_pSignAsset; }
			if (!selected) return false;
			ZSignAsset libraryAsset = *selected;
			libraryAsset.m_strEntitleData.clear();
			ZMachO macho;
			if (!macho.Init(fullPath.c_str()) || !macho.Sign(&libraryAsset, true, identifier, string(20, 0), string(32, 0), "")) return false;
		}
	}
"""
        + text[loose_end:]
    )
    begin = text.index("\tif (m_pSignAssets) {", text.index("// The matched profile"))
    end = text.index("\n\tZFile::CreateFolderV", begin)
    text = (
        text[:begin]
        + """\tjvalue plan;
\tif (m_strIsignPlan.empty() || !plan.read_from_file(m_strIsignPlan.c_str()) || !plan.has(strFolder.c_str())) { return false; }
\tjvalue node = plan[strFolder];
\tif (node["bundleId"].as_string() != strBundleId) { return false; }
\tif (node["kind"].as_string() != "app" && node["kind"].as_string() != "appex" && node["kind"].as_string() != "framework") return false;
\tconst bool framework = node["kind"].as_string() == "framework";
\tconst string applicationId = node["applicationId"];
\tZSignAsset* selected = NULL;
\tif (m_pSignAssets) {
\t\tfor (auto &asset : *m_pSignAssets) { if (asset.m_strApplicationId == applicationId) { if (selected) return false; selected = &asset; } }
\t} else if (m_pSignAsset->m_strApplicationId == applicationId) { selected = m_pSignAsset; }
\tif (!selected) { return false; }
\tm_pSignAsset = selected;
\tif (framework) { m_pSignAsset->m_strEntitleData.clear(); }
\telse {
\t\tstring entitlementPath = node["entitlementsPath"];
\t\tif (!ZFile::ReadFile(entitlementPath.c_str(), m_pSignAsset->m_strEntitleData)) { return false; }
\t\tjvalue ent; ent.read_plist(m_pSignAsset->m_strEntitleData);
\t\tif (ent["application-identifier"].as_string() != applicationId) return false;
\t\tif (!ZFile::WriteFileV(m_pSignAsset->m_strProvData, "%s/embedded.mobileprovision", strBaseFolder.c_str())) return false;
\t}
\tbForceSign = true;
"""
        + text[end:]
    )
    text = text.replace(
        'if (ZFile::IsPathSuffix(strKey, ".lproj/locversion.plist")) {', "if (false) {"
    ).replace(
        'if (ZFile::IsPathSuffix(strKey, ".DS_Store") || "Info.plist" == strKey || "PkgInfo" == strKey) {',
        'if ("Info.plist" == strKey || "PkgInfo" == strKey) {',
    )
    # locversion.plist is sealed by this strict driver; its rules must not
    # silently exempt the same file during Apple's resource validation.
    text = "\n".join(
        line for line in text.split("\n") if ']["^.*\\\\.lproj/locversion.plist$"]' not in line
    )
    text = text.replace(
        "ZBundle::ZBundle()",
        r"""
static bool IsignProfilePermits(ZSignAsset& asset, const string& applicationId)
{
    string content; jvalue profile;
    if (!ZSignAsset::GetCMSContent(asset.m_strProvData, content) || !profile.read_plist(content)) return false;
    if (profile["ApplicationIdentifierPrefix"].size() != 1) return false;
    string prefix = profile["ApplicationIdentifierPrefix"][0];
    if (prefix.empty() || prefix.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") != string::npos) return false;
    string start = prefix + ".";
    string pattern = profile["Entitlements"]["application-identifier"];
    if (applicationId.compare(0, start.size(), start) != 0 || pattern.compare(0, start.size(), start) != 0 || applicationId.find('*') != string::npos) return false;
    string concrete = applicationId.substr(start.size());
    if (concrete.empty() || concrete.find('.') == string::npos || concrete.front() == '.' || concrete.back() == '.' || concrete.find("..") != string::npos || concrete.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.") != string::npos) return false;
    size_t wildcard = pattern.find('*');
    if (wildcard == string::npos) return pattern == applicationId;
    if (wildcard != pattern.size() - 1 || (wildcard != start.size() && pattern[wildcard - 1] != '.')) return false;
    string scope = pattern.substr(start.size(), wildcard - start.size());
    if (scope.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.") != string::npos || scope.find("..") != string::npos || (!scope.empty() && scope.front() == '.')) return false;
    return applicationId.compare(0, wildcard, pattern, 0, wildcard) == 0 && applicationId.size() > wildcard;
}

static bool IsignProfileDigest(ZSignAsset& asset, const string& expected)
{
    if (expected.size() != 64 || expected.find_first_not_of("0123456789abcdef") != string::npos) return false;
    string digest;
    if (!ZSHA::SHA256(asset.m_strProvData, digest)) return false;
    string hex;
    for (unsigned char byte : digest) { char pair[3]; snprintf(pair, sizeof(pair), "%02x", byte); hex += pair; }
    return hex == expected;
}

"""
        + "ZBundle::ZBundle()",
    )
    text = text.replace(
        "asset.m_strApplicationId == applicationId",
        'IsignProfileDigest(asset, node["profileDigest"].as_string())',
    )
    text = text.replace(
        "m_pSignAsset->m_strApplicationId == applicationId",
        'IsignProfileDigest(*m_pSignAsset, node["profileDigest"].as_string())',
    )
    text = text.replace(
        "if (!selected) return false;",
        "if (!selected || !IsignProfilePermits(*selected, applicationId)) return false;",
    )
    text = text.replace(
        "if (!selected) { return false; }",
        "if (!selected || !IsignProfilePermits(*selected, applicationId)) { return false; }",
    )
    cpp.write_text(text)
    sha = destination / "src/common/sha.cpp"
    text = sha.read_text().replace(
        "#include <openssl/sha.h>",
        "#include <openssl/sha.h>\n#include <openssl/evp.h>\n#include <cstdio>",
    )
    start = text.index("\tsize_t sSize = 0;", text.index("bool ZSHA::SHAFile("))
    end = text.index("\n}\n", start)
    text = (
        text[:start]
        + r"""	FILE* file = fopen(szFile, "rb");
	if (!file) return false;
	EVP_MD_CTX* one = EVP_MD_CTX_new();
	EVP_MD_CTX* two = EVP_MD_CTX_new();
	bool ok = one && two && EVP_DigestInit_ex(one, EVP_sha1(), NULL) == 1 && EVP_DigestInit_ex(two, EVP_sha256(), NULL) == 1;
	unsigned char buffer[65536];
	while (ok) {
		size_t count = fread(buffer, 1, sizeof(buffer), file);
		if (count) ok = EVP_DigestUpdate(one, buffer, count) == 1 && EVP_DigestUpdate(two, buffer, count) == 1;
		if (count < sizeof(buffer)) { if (ferror(file)) ok = false; break; }
	}
	unsigned char first[EVP_MAX_MD_SIZE], second[EVP_MAX_MD_SIZE];
	unsigned int firstSize = 0, secondSize = 0;
	if (ok) ok = EVP_DigestFinal_ex(one, first, &firstSize) == 1 && EVP_DigestFinal_ex(two, second, &secondSize) == 1 && firstSize == 20 && secondSize == 32;
	EVP_MD_CTX_free(one); EVP_MD_CTX_free(two);
	if (fclose(file) != 0) ok = false;
	if (!ok) return false;
	strSHA1.assign((const char*)first, firstSize);
	strSHA256.assign((const char*)second, secondSize);
	return true;"""
        + text[end:]
    )
    text = text.replace(
        "SHAFile(szFile, strSHA1, strSHA256);",
        "if (!SHAFile(szFile, strSHA1, strSHA256)) { strSHA1Base64.clear(); strSHA256Base64.clear(); return false; }",
    )
    sha.write_text(text)
    return {path: hashlib.sha256((destination / path).read_bytes()).hexdigest() for path in PINS}
