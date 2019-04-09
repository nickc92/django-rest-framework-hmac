import hmac
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from rest_framework_hmac.client import HMACAuthenticator, get_request_field

class HMACAuthentication(BaseAuthentication):

    def authenticate(self, request):
        signature = self.get_signature(request)
        user = self.get_user(request)
        nonce = self.get_nonce(request)

        b64 = HMACAuthenticator(user).calc_signature(request)

        if not hmac.compare_digest(b64, signature):
            raise AuthenticationFailed()

        if nonce <= user.hmac_key.nonce:
            raise Exception('Supplied nonce is unacceptable!')

        user.hmac_key.nonce = nonce
        user.hmac_key.save()

        return (user, None)

    @staticmethod
    def get_user(request):
        from django.contrib.auth import get_user_model
        UserModel = get_user_model()

        try:
            return UserModel.objects.get(hmac_key__key=get_request_field(request, 'Key'))
        except (KeyError, UserModel.DoesNotExist):
            raise AuthenticationFailed()

    @staticmethod
    def get_signature(request):
        try:
            signature = get_request_field(request, 'Signature')
            if isinstance(signature, str):
                signature = signature.encode('utf-8')
        except KeyError:
            raise AuthenticationFailed()

        if not isinstance(signature, bytes):
            raise AuthenticationFailed()

        return signature

    @staticmethod    
    def get_nonce(request):
        try:
            nonce = int(get_request_field(request, 'Nonce'))
        except KeyError:
            raise AuthenticationFailed()
        except:
            raise AuthenticationFailed()
        
        return nonce
    
