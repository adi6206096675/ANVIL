# engine/sast/manifest_scanner.py
import xml.etree.ElementTree as ET
import os

class ManifestAuditor:
    """Audits decompiled Android Manifests for security misconfigurations."""
    
    def audit_manifest(self, manifest_path: str) -> list:
        findings = []
        if not manifest_path or not os.path.exists(manifest_path):
            return findings

        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            ns = {'android': 'http://schemas.android.com/apk/res/android'}

            # 1. Check Debuggable Flag
            application = root.find('application')
            if application is not None:
                debuggable = application.get('{http://schemas.android.com/apk/res/android}debuggable')
                if debuggable == 'true':
                    findings.append({
                        "severity": "CRITICAL",
                        "type": "Debuggable App Flag Enabled",
                        "detail": "android:debuggable='true' allows process attachment and runtime injection."
                    })

                allow_backup = application.get('{http://schemas.android.com/apk/res/android}allowBackup')
                if allow_backup == 'true':
                    findings.append({
                        "severity": "MEDIUM",
                        "type": "Application Backup Enabled",
                        "detail": "android:allowBackup='true' allows ADB data extraction."
                    })

            # 2. Audit Exported IPC Components (Activities, Services, Receivers)
            for component_type in ['activity', 'service', 'receiver', 'provider']:
                for item in root.findall(f'.//{component_type}'):
                    exported = item.get('{http://schemas.android.com/apk/res/android}exported')
                    name = item.get('{http://schemas.android.com/apk/res/android}name')
                    if exported == 'true':
                        findings.append({
                            "severity": "HIGH",
                            "type": f"Exported {component_type.capitalize()}",
                            "detail": f"Component '{name}' is publicly accessible to other apps."
                        })

        except ET.ParseError:
            # Manifest might be compiled binary XML if apktool was not used
            findings.append({
                "severity": "INFO",
                "type": "Binary Manifest",
                "detail": "Manifest is in binary XML format. Install apktool for full text decoding."
            })

        return findings