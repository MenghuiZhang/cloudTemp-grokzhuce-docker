import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReleaseImageTests(unittest.TestCase):
    def test_release_image_reuses_v14_runtime(self):
        dockerfile = (ROOT / "Dockerfile.release").read_text(encoding="utf-8")
        self.assertIn(
            "ARG GROK_RUNTIME_IMAGE=ghcr.io/menghuizhang/"
            "cloudtemp-grokzhuce-docker:v1.4.0",
            dockerfile,
        )
        self.assertIn("FROM ${GROK_RUNTIME_IMAGE}", dockerfile)
        self.assertIn("COPY . .", dockerfile)

        # Reinstalling either dependency set would recreate the v1.5 runtime
        # drift that this release image is specifically meant to avoid.
        self.assertNotIn("pip install", dockerfile)
        self.assertNotIn("camoufox fetch", dockerfile)

    def test_publish_workflow_uses_release_dockerfile(self):
        workflow = (
            ROOT / ".github" / "workflows" / "publish-image.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("file: Dockerfile.release", workflow)


if __name__ == "__main__":
    unittest.main()
