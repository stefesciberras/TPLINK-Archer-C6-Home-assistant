import hassapi as hass

from datetime import datetime, timedelta
import logging
import requests

class InternetAllowance(hass.Hass):
    def initialize(self):
        # get a requests session
        self.session = requests.Session()

        self.log ("Internet Allowance Appdaemon running...")
        self.Timers = {'mon': 0, 'tue': 0, 'wed': 0, 'thu': 0, 'fri': 0, 'sat': 0, 'sun': 0}
        self.TimerHandlers = {'mon': 0, 'tue': 0, 'wed': 0, 'thu': 0, 'fri': 0, 'sat': 0, 'sun': 0}
        self.DelayHandle = 0
        
        DaysOfTheWeek = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
        
        for x in DaysOfTheWeek:
            print(x)
            self.Timers[x] = self.get_state("input_datetime.internet_off_time_%s" % (x))
            self.setTimeToOff ( x, self.Timers[x])

        self.listen_state(self.TimerChanged, ["input_datetime.internet_off_time_mon","input_datetime.internet_off_time_tue","input_datetime.internet_off_time_wed","input_datetime.internet_off_time_thu","input_datetime.internet_off_time_fri","input_datetime.internet_off_time_sat","input_datetime.internet_off_time_sun"])
        
        print (self.Timers)
        self.log ("Running...")
        schedule = self.get_scheduler_entries()
        self.log (schedule)
        
    def TimerChanged (self, entity, attribute, old, new, kwargs):
        self.log ("New time set....")
        DayOfWeek = entity[-3:]
        self.log (DayOfWeek)
        self.log (self.TimerHandlers)
        self.log (self.TimerHandlers[DayOfWeek])

        self.cancel_timer(self.TimerHandlers[DayOfWeek])
        self.log ("*****")
        self.cancel_timer(self.DelayHandle) #Just in case the timer has gone off within the delay time
        
        self.Timers[DayOfWeek] = self.get_state(entity)
        self.setTimeToOff (DayOfWeek, new)
        
        self.log (self.Timers)
        schedule = self.get_scheduler_entries()
        self.log (schedule)
        return
        
        
    def setTimeToOff (self, DayToSet, TimeToSet):
        # This is an alarm for the night, so values should be from 22:00 to morning.
        # This means that a value earlier than 6am should be treated as an alarm for the following day
        # eg Friday 1am means 1am in night between Friday and Saturday so alarm to be set at 1am Saturday.
        # if so, DayToSet is to be increased by 1.
        
        ## Please check, it seems the night is treated as part of the day for the constrain part.
        
        ConstrainDayToSet = DayToSet
        if self.parse_time(TimeToSet) < self.parse_time("06:00:00"):
            DaysOfTheWeek = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
            currentDay = DaysOfTheWeek.index(DayToSet)
            ConstrainDayToSet = DaysOfTheWeek [currentDay] # + 1] to check!!!!!  **************
        
        handle = self.run_daily( self._TimeIsUp, TimeToSet, constrain_days=ConstrainDayToSet, DayOfWeek=DayToSet)
        if self.timer_running(handle):
            self.log ("Handle is:")
            self.log (handle)
            self.TimerHandlers[DayToSet] = handle
            self.log (self.info_timer(handle))
            self.log (self.TimerHandlers[DayToSet])

        else:
            self.log ("Not set")
            
        return
    
    def notifyAndDelay (self, a):
        self.notify("Your internet will be blocked in 5 minutes until tomorrow", title = "Internet Blocked", name = "mobile_app_katrina")
        self.notify("Katrina's internet will be blocked in 5 minutes until tomorrow", title = "Internet Blocked (%s)" % (a['DayOfWeek']), name = "mobile_app_stefe_iphone")
        self.DelayHandle = self.run_in(self.blockInternet, 600)
        
        
    def blockInternet (self, kwargs):
        self.log("Now blocking internet...")
        self.turn_on("input_boolean.block_katrina")
        

    def _TimeIsUp ( self, a ):
        self.log ("**************************************")
        self.log ("Time is up!")
        self.log (a)
        isEnabled = self.get_state("input_boolean.internet_off_%s" % (a['DayOfWeek']))
        if isEnabled == 'on':
            self.log ("Blocking is enabled") 
            self.log ( a )
            self.notifyAndDelay ( a )
        else:
            self.log ("Blocking is disabled")