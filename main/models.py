from django.db import models

class Blockedclient(models.Model):
    
    client_ip=models.CharField(null=True,blank=True ,max_length=100)
    date=models.DateField(auto_now_add=True)
    path=models.CharField(max_length=20)
    endpoint=models.CharField( max_length=100)
    overview=models.CharField( max_length=15)
    
    
    
    def __str__(self):
        return str(self.id)


class Pattern(models.Model):
    
    name=models.CharField( max_length=100)
    is_enabled=models.BooleanField(default=False)
    
    
    def __str__(self):
        return self.name