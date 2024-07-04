#!/bin/bash
gsettings set org.gnome.desktop.session idle-delay 600

gsettings set org.gnome.desktop.screensaver idle-activation-enabled true

gsettings set org.gnome.desktop.screensaver lock-enabled true

gsettings set org.gnome.desktop.screensaver lock-delay 600

gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type bool \
--set /apps/gdm/simple-greeter/banner_message_enable true

gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type bool --set /apps/gdm/simple-greeter/disable_user_list true

gconftool-2 \
--direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type string \
--set /apps/gnome-screensaver/mode blank-only

gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type string \
--set /apps/gnome_settings_daemon/keybindings/screensaver "<Control><Alt>l"

gconftool-2 \
--direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type string \
--set /apps/gdm/simple-greeter/banner_message_text \
"I've read & consent to terms in IS user agreem't."
