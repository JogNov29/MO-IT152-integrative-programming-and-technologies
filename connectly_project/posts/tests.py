from django.test import TestCase

# Create your tests here.
from posts.singletons.config_manager import ConfigManager   # Import the ConfigManager class from the posts app

class ConfigManagerTestCase(TestCase):
    
    def test_singleton_behavior(self):
        # Create two instances of ConfigManager
        config1 = ConfigManager()
        config2 = ConfigManager()

        # Assert that both instances are the same object (Singleton behavior)
        self.assertIs(config1, config2)  # Both instances should be the same

    def test_setting_persistence(self):
        # Ensure that settings are consistent across instances
        config1 = ConfigManager()
        config1.set_setting("DEFAULT_PAGE_SIZE", 50)

        # Fetch the setting from the second instance (should be the same)
        config2 = ConfigManager()
        self.assertEqual(config2.get_setting("DEFAULT_PAGE_SIZE"), 50)
        
    def test_initial_settings(self):
        # Verify that default settings are initialized correctly
        config = ConfigManager()
        self.assertEqual(config.get_setting("DEFAULT_PAGE_SIZE"), 20)
        self.assertEqual(config.get_setting("ENABLE_ANALYTICS"), True)
        self.assertEqual(config.get_setting("RATE_LIMIT"), 100)