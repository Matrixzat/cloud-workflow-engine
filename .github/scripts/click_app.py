import sys, re, subprocess, xml.etree.ElementTree as ET

adb      = sys.argv[1] if len(sys.argv) > 1 else "adb"
xml_file = sys.argv[2] if len(sys.argv) > 2 else "/tmp/uidump.xml"
keywords = ["sapa", "Sapa", "livetv", "mobile31027704", "LiveTV", "Mobile Sapa", "TV"]

try:
    tree = ET.parse(xml_file)
    for node in tree.getroot().iter("node"):
        text = node.get("text","") + node.get("content-desc","") + node.get("resource-id","")
        if any(k.lower() in text.lower() for k in keywords):
            bounds = node.get("bounds","")
            nums = re.findall(r"\d+", bounds)
            if len(nums) >= 4:
                x = (int(nums[0]) + int(nums[2])) // 2
                y = (int(nums[1]) + int(nums[3])) // 2
                print(f"Tapping '{text[:50]}' at ({x},{y})")
                subprocess.run([adb, "shell", "input", "tap", str(x), str(y)])
                sys.exit(0)
    print("App not found in current BlackDex UI view")
except Exception as e:
    print(f"Error: {e}")
