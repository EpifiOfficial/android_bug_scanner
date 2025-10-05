import os
import subprocess
import re
import shutil
import tempfile
from androguard.misc import AnalyzeAPK
from androguard.core.analysis.analysis import ExternalMethod

# Define the directory where your Android SDK and tools are located
ANDROID_TOOLS_DIR = "<path_to_android_sdk>/build-tools/"

# Paths to other tools like JADX and APKTool could be useful for decompilation and inspection
JADX_PATH = "<path_to_jadx>"
APKTOOL_PATH = "<path_to_apktool>"

class AndroidBugScanner:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.report = []
        self.apk_analysis()  # Starts the analysis during instantiation
        
    def apk_analysis(self):
        # Analyze APK with Androguard
        a, d, dx = AnalyzeAPK(self.apk_path)
        
        # Static Analysis for Dangerous API Usages
        self.scan_dangerous_permissions(a)
        self.scan_vulnerable_code(dx)
        
        # Present Report
        self.generate_report()

    def scan_dangerous_permissions(self, apk):
        permissions = apk.get_permissions()
        dangerous_permissions = ["android.permission.SEND_SMS", "android.permission.WRITE_EXTERNAL_STORAGE"]

        for permission in dangerous_permissions:
            if permission in permissions:
                self.report.append(f"Potential Risk: {permission} is requested.")

    def scan_vulnerable_code(self, dx):
        # Find the usage of external methods, which may be a potential vulnerability
        for method in dx.get_methods():
            # External methods are potential entry points for risky behaviour
            if method.is_external():
                # Checking for potentially insecure methods
                if "java.net.HttpURLConnection" in method.class_name:
                    self.report.append(
                        f"Potential Insecure HTTP Call in Method: {method.name} in class {method.class_name}"
                    )

    def generate_report(self):
        report_file = os.path.splitext(os.path.basename(self.apk_path))[0] + "_bug_report.txt"
        with open(report_file, "w") as f:
            for item in self.report:
                f.write(f"{item}\n")

        print(f"Report generated: {report_file}")

if __name__ == "__main__":
    apk_path = "<path_to_apk>"
    scanner = AndroidBugScanner(apk_path)
