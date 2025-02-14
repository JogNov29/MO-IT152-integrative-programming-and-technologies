class ConfigManager:
    # This is a class-level variable that holds the single instance of ConfigManager
    _instance = None

    def __new__(cls, *args, **kwargs):
        """
        The __new__ method ensures that only one instance of ConfigManager is created
        (Singleton pattern).
        
        When the ConfigManager class is instantiated, this method checks if an instance
        already exists. If not, it creates one.
        """
        # If _instance is None, it means this is the first time the ConfigManager is being instantiated.
        if not cls._instance:
            # Create the instance using the parent class's __new__ method.
            cls._instance = super(ConfigManager, cls).__new__(cls, *args, **kwargs)
            
            # Initialize the instance with default configuration values.
            cls._instance._initialize()
        
        # Return the single instance of ConfigManager, whether it's the first time or not.
        return cls._instance

    def _initialize(self):
        """
        Initialize the settings for the ConfigManager. This method sets up the default configuration.
        """
        # Dictionary that stores default configuration settings for the application.
        self.settings = {
            "DEFAULT_PAGE_SIZE": 20,  # Default page size for pagination
            "ENABLE_ANALYTICS": True,  # Flag to enable or disable analytics
            "RATE_LIMIT": 100         # Rate limit for API requests
        }

    def get_setting(self, key):
        """
        Retrieve the value of a configuration setting by its key.
        
        Arguments:
        - key: The key for which the setting value needs to be retrieved (string).
        
        Returns:
        - The value of the setting (can be any type, depending on what is stored in settings).
        """
        # Get the value from the settings dictionary using the provided key.
        return self.settings.get(key)

    def set_setting(self, key, value):
        """
        Set or update the value of a configuration setting.
        
        Arguments:
        - key: The key for the setting you want to update.
        - value: The new value to assign to the setting.
        
        This method allows for modifying configuration values after initialization.
        """
        # Set or update the configuration setting in the dictionary.
        self.settings[key] = value
