import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure project root is in sys.path
root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from src.noxpwn.utils import (
    save_to_file, read_file, merge_lists, check_tool, setup_environment_paths, run_cmd
)


class TestUtils(unittest.TestCase):
    def test_setup_environment_paths(self):
        setup_environment_paths()
        self.assertIn("PATH", os.environ)

    def test_save_and_read_file(self):
        with tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8") as tf:
            tf_path = tf.name

        try:
            sample_data = ["https://sub1.example.com", "https://sub2.example.com"]
            save_to_file(tf_path, sample_data)
            read_back = read_file(tf_path)
            self.assertEqual(read_back, sample_data)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_merge_lists(self):
        with tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8") as tf1:
            tf1.write("a\nb\nc\n")
            p1 = tf1.name

        with tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8") as tf2:
            tf2.write("b\nc\nd\n")
            p2 = tf2.name

        try:
            merged = merge_lists([p1, p2])
            self.assertEqual(merged, ["a", "b", "c", "d"])
        finally:
            if os.path.exists(p1):
                os.remove(p1)
            if os.path.exists(p2):
                os.remove(p2)

    def test_run_cmd_stdin_text(self):
        # Cross-platform python invocation via stdin
        import sys
        rc, out, _ = run_cmd(
            f'"{sys.executable}" -c "import sys; print(sys.stdin.read().strip())"',
            stdin_text="noxpwn_test_payload"
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "noxpwn_test_payload")

    def test_run_cmd_stdin_file(self):
        import sys
        with tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8") as tf:
            tf.write("file_payload_test\n")
            p = tf.name

        try:
            rc, out, _ = run_cmd(
                f'"{sys.executable}" -c "import sys; print(sys.stdin.read().strip())"',
                stdin_file=p
            )
            self.assertEqual(rc, 0)
            self.assertEqual(out.strip(), "file_payload_test")
        finally:
            if os.path.exists(p):
                os.remove(p)


if __name__ == "__main__":
    unittest.main()
