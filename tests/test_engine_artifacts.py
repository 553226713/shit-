import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine2.artifacts import installed_engine, installed_textconv


class InstalledArtifactsTests(unittest.TestCase):
    def resources(self, root):
        (root/'lib').mkdir()
        manifest={}
        for name,field in [('ytfs-engine2','engine2_sha256'),('ytfs-textconv','textconv_sha256'),
                           ('lib/libfuse3.so.4','libfuse_sha256')]:
            data=('fixture '+name).encode();(root/name).write_bytes(data)
            manifest[field]=hashlib.sha256(data).hexdigest()
        (root/'manifest.json').write_text(json.dumps(manifest))

    def test_uses_installed_resources_without_writing_or_copying(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);self.resources(root)
            before={str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertEqual(installed_engine(root),root/'ytfs-engine2')
            self.assertEqual(installed_textconv(root),root/'ytfs-textconv')
            self.assertEqual(before,{str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()})

    def test_rejects_modified_dynamic_library(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);self.resources(root)
            (root/'lib/libfuse3.so.4').write_bytes(b'modified')
            with self.assertRaisesRegex(ValueError,'libfuse3'):installed_engine(root)

    def test_missing_installed_helper_is_an_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);self.resources(root)
            (root/'ytfs-textconv').unlink()
            with self.assertRaisesRegex(ValueError,'ytfs-textconv'):installed_textconv(root)
