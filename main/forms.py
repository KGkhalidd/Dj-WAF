from django import forms
from .models import Pattern,Blockedclient

class Patternform(forms.ModelForm):
  class Meta:
    model=Pattern
    fields ='__all__'
    
class Blockedclientform(forms.ModelForm):
  class Meta:
    model=Blockedclient
    fields =("client_ip","id",)
    

    
