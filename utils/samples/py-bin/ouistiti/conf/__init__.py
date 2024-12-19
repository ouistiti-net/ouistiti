from ouistiti.conf import global_settings

class Settings:
    def __init__(self):
        for setting in dir(global_settings):
            setattr(self, setting, getattr(global_settings, setting))

    def configure(self, default_settings):
        for setting in dir(default_settings):
            setattr(self, setting, getattr(default_settings, setting))

settings = Settings()
