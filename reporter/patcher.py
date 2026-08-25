# reporter/patcher.py
import os

class AnvilAutoPatcher:
    """Safely injects remediation code into vulnerable source files."""
    
    def apply_patch(self, filepath: str, target_line: int, patch_code: str, vuln_type: str) -> str:
        """
        Creates a .patched version of the file, commenting out the vulnerable line
        and injecting the recommended security fix.
        """
        if not os.path.exists(filepath):
            return f"Error: File {filepath} not found."

        patched_filepath = f"{filepath}.patched"
        
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()
            
            # Adjust to zero-indexed list
            line_idx = target_line - 1 
            
            if 0 <= line_idx < len(lines):
                original_line = lines[line_idx]
                indentation = " " * (len(original_line) - len(original_line.lstrip()))
                
                # Format the patch code to match the file's indentation
                formatted_patch = "\n".join([f"{indentation}{line}" for line in patch_code.strip().split("\n")])
                
                # Comment out the vulnerable line and inject the patch
                lines[line_idx] = f"{indentation}# [ANVIL AUTO-PATCH REMOVED] {original_line.lstrip()}"
                lines.insert(line_idx + 1, f"{indentation}# [ANVIL AUTO-PATCH APPLIED: {vuln_type}]\n{formatted_patch}\n")
                
                with open(patched_filepath, "w", encoding="utf-8") as f:
                    f.writelines(lines)
                
                return patched_filepath
            else:
                return "Error: Target line out of bounds."
                
        except Exception as e:
            return f"Error applying patch: {e}"