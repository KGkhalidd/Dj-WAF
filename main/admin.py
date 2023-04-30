from django.contrib import admin
from .models import Blockedclient, Pattern

class PatternAdmin(admin.ModelAdmin):
    list_display = ["name","is_enabled"]
    
class BlockedclientAdmin(admin.ModelAdmin):
    list_display =["client_ip","date","path","overview","endpoint"]

admin.site.register(Blockedclient,BlockedclientAdmin)
admin.site.register(Pattern,PatternAdmin)
