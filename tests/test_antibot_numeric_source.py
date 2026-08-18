import unittest

from g.antibot_service import _is_numeric_bot_flag_source


class NumericBotFlagSourceTests(unittest.TestCase):
    def test_one_and_two_are_hard_signals(self):
        for value in (1, 2, 1.0, 2.0, "1", "2", " 2 "):
            with self.subTest(value=value):
                self.assertTrue(_is_numeric_bot_flag_source(value))

    def test_other_values_are_not_numeric_hard_signals(self):
        for value in (None, "", 0, "0", 3, "BOT_FLAG_SOURCE_CASTLE", True):
            with self.subTest(value=value):
                self.assertFalse(_is_numeric_bot_flag_source(value))


if __name__ == "__main__":
    unittest.main()
