from burp import IBurpExtender
from burp import ISessionHandlingAction
SESSION_ID_KEY = "\nmsg:5"
SESSION_ID_KEY_BYTES = bytearray(SESSION_ID_KEY)
NEWLINE_BYTES = bytearray("\r\n")

class BurpExtender(IBurpExtender, ISessionHandlingAction):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # save the helpers for later
        self.helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Session token example")
        callbacks.registerSessionHandlingAction(self)

    #
    # Implement ISessionHandlingAction
    #

    def getActionName(self):
        return "Use session token from macro"

    def performAction(self, current_request, macro_items):
        if len(macro_items) == 0:
            return

        # extract the response headers
        final_response = macro_items[len(macro_items) - 1].getResponse()
        if final_response is None:
            return
        else:
            final_response = final_response[2820:2857]


            

        req = current_request.getRequest()
        #req = req[:-44]
        session_token_key_start = self.helpers.indexOf(req, SESSION_ID_KEY_BYTES, False, 0, len(req))

        # glue together first line + session token header + rest of request
        current_request.setRequest(
                    req[:session_token_key_start] + self.helpers.stringToBytes("%s" % (SESSION_ID_KEY))+final_response)