# engine/decompiler/pipeline.py
import os
import shutil
import zipfile
import subprocess
import xml.etree.ElementTree as ET

class AnvilDecompilerPipeline:
    """
    Deconstructs compiled applications into analyzed components:
    Manifests, Source Code, Native Binaries, and Embedded Storage.
    """
    def __init__(self, workspace_dir: str = "tests/samples/decompiled_app"):
        self.workspace_dir = workspace_dir

    def prepare_workspace(self):
        """Cleans and re-creates the workspace directory."""
        if os.path.exists(self.workspace_dir):
            shutil.rmtree(self.workspace_dir)
        os.makedirs(self.workspace_dir, exist_ok=True)

    def decompile(self, app_path: str) -> dict:
        """Main entry point to shatter an app into pieces."""
        self.prepare_workspace()
        
        pieces = {
            "manifest": None,
            "source_dir": os.path.join(self.workspace_dir, "sources"),
            "native_libs": [],
            "assets": [],
            "configs": [],
            "status": "SUCCESS"
        }

        if not os.path.exists(app_path):
            pieces["status"] = f"ERROR: File '{app_path}' not found."
            return pieces

        print(f"[ANVIL DECOMPILER] Shattering target application: {app_path}")

        # --- 1. DECOMPILE AND EXTRACT ARCHIVE STRUCTURE ---
        if app_path.endswith(".apk"):
            self._decompile_apk(app_path, pieces)
        elif app_path.endswith(".zip"):
            self._unpack_zip(app_path, pieces)
        else:
            # Single script/binary mode
            pieces["source_dir"] = app_path

        # --- 2. INDEX EXTRACTED PIECES ---
        self._index_components(pieces)

        return pieces

    def _decompile_apk(self, apk_path: str, pieces: dict):
        """Decompiles Android APK using JADX or raw ZIP extraction fallback."""
        jadx_bin = shutil.which("jadx")
        
        if jadx_bin:
            print("[ANVIL DECOMPILER] Executing JADX engine for full Java source reconstruction...")
            subprocess.run(
                [jadx_bin, "-d", self.workspace_dir, "--export-as-java", apk_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        else:
            print("[ANVIL DECOMPILER] JADX not on PATH. Falling back to native ZIP unpacking...")
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(self.workspace_dir)

    def _unpack_zip(self, zip_path: str, pieces: dict):
        """Unpacks standard zip archives."""
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(self.workspace_dir)

    def _index_components(self, pieces: dict):
        """Categorizes all decompiled files into structural components."""
        if not os.path.isdir(self.workspace_dir):
            return

        for root, _, files in os.walk(self.workspace_dir):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, self.workspace_dir)

                # Categorize Manifest & Configs
                if file.lower() in ["androidmanifest.xml", "config.json", "settings.json", ".env"]:
                    if file.lower() == "androidmanifest.xml":
                        pieces["manifest"] = file_path
                    pieces["configs"].append(file_path)

                # Categorize Native Binaries
                elif file.endswith((".so", ".dll", ".dylib", ".exe")):
                    pieces["native_libs"].append(file_path)

                # Categorize Databases & Storage Assets
                elif file.endswith((".db", ".sqlite", ".plist", ".properties", ".pem", ".key")):
                    pieces["assets"].append(file_path)

        print(f"[ANVIL DECOMPILER] Decompilation complete:")
        print(f"  • Source Directory : {pieces['source_dir']}")
        print(f"  • Native Libraries  : {len(pieces['native_libs'])} found")
        print(f"  • Config/Manifests  : {len(pieces['configs'])} found")
        print(f"  • Storage Assets    : {len(pieces['assets'])} found")


if __name__ == "__main__":
    decompiler = AnvilDecompilerPipeline()
    # Test against a local archive or APK
    result = decompiler.decompile("tests/samples/vuln.py")