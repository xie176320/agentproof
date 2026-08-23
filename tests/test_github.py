import unittest

from agentproof.github import GitHubFetchError, parse_public_repo_url


class GitHubTests(unittest.TestCase):
    def test_parses_public_repo(self) -> None:
        self.assertEqual(
            parse_public_repo_url("https://github.com/openai/openai-python"), ("openai", "openai-python")
        )

    def test_parses_dot_git_suffix(self) -> None:
        self.assertEqual(parse_public_repo_url("https://github.com/owner/repo.git"), ("owner", "repo"))

    def test_rejects_non_github_host(self) -> None:
        with self.assertRaises(GitHubFetchError):
            parse_public_repo_url("https://example.com/owner/repo")

    def test_rejects_nested_url(self) -> None:
        with self.assertRaises(GitHubFetchError):
            parse_public_repo_url("https://github.com/owner/repo/tree/main")

    def test_rejects_http(self) -> None:
        with self.assertRaises(GitHubFetchError):
            parse_public_repo_url("http://github.com/owner/repo")


if __name__ == "__main__":
    unittest.main()
