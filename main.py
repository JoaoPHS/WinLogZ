from gui import Winlogz
import traceback

if __name__ == "__main__":
    try:
        print("Starting WinLogZ...")
        app = Winlogz()
        app.run()
    except Exception as e:
        print("Error during initialization:")
        print(traceback.format_exc())
        input("Press Enter to exit...")