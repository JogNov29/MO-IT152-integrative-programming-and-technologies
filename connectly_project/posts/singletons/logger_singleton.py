import logging

class LoggerSingleton:
    # Class-level variable to hold the single instance of the LoggerSingleton
    _instance = None

    def __new__(cls, *args, **kwargs):
        """
        __new__ is used to ensure that only one instance of LoggerSingleton is created
        (Singleton pattern).

        The first time the LoggerSingleton class is instantiated, this method creates
        the instance. On subsequent instantiations, it returns the same instance.
        """
        # Check if an instance of LoggerSingleton already exists
        if not cls._instance:
            # If the instance doesn't exist, create it
            cls._instance = super(LoggerSingleton, cls).__new__(cls, *args, **kwargs)
            
            # Initialize the logger instance after it's created
            cls._instance._initialize()
        
        # Return the single instance of LoggerSingleton
        return cls._instance

    def _initialize(self):
        """
        This method sets up the logger configuration.

        It is called only once when the LoggerSingleton instance is created.
        It configures the logger to print logs to the console with a specific format.
        """
        # Create a logger named 'connectly_logger'
        self.logger = logging.getLogger("connectly_logger")

        # Create a stream handler to output logs to the console (stdout)
        handler = logging.StreamHandler()

        # Define a log format (timestamp, log level, and message)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        # Set the format for the handler
        handler.setFormatter(formatter)

        # Add the handler to the logger
        self.logger.addHandler(handler)

        # Set the default logging level to INFO (logs at this level and above will be recorded)
        self.logger.setLevel(logging.INFO)

    def get_logger(self):
        """
        This method provides access to the logger instance.
        
        It ensures that only one logger instance exists (thanks to the Singleton pattern),
        and it's returned when needed to log messages.
        """
        return self.logger
