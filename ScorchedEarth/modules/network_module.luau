local DETECTION_SIGNALS = {
    ["233"] = function(vargs)
        rconsolewarn"BLOCKED DETECTION '233' [INSTANCE_DETECTED]";
    end,
    ["155"] = function(vargs)
        rconsolewarn"BLOCKED DETECTION '155' [INSTANCE_DETECTED]";
    end,
    ["234"] = function(vargs)
        rconsolewarn"BLOCKED DETECTION '234' [INSTANCE_DETECTED_OR_COREGUI_WEAKT]";
    end,
    ["235"] = function(vargs)
        rconsolewarn"BLOCKED DETECTION '235' [SCRIPT_CONTEXT_ERROR]";
    end,
    ["236"] = function(vargs)
        rconsolewarn"BLOCKED DETECTION '236' [SIGNALS/NETWORK_MODULE_TAMPER]";
    end,
    ["237"] = function(vargs)
        rconsolewarn"BLOCKED DETECTION '237' [_G_VAR_DETECTED]";
    end,
    ["envSpoof"] = function(vargs)
        rconsolewarn"BLOCKED DETECTION '206' [GETFENV_TRAP_TRIGGERED]";
    end,
    ["103"] = function(vargs)
        rconsolewarn"BLOCKED DETECTION '103' [GETFENV_TRAP_TRIGGERED]";
    end
};

local fire;

for k, v in getgc(true) do
    if type(v) == "table" and type(rawget(v, "fireUnreliable")) == "function" then
        fire = rawget(v, "fire");
        break;
    end
end

local encode = debug.getupvalue(fire, 2);
local remote = debug.getupvalue(fire, 3);

hookfunction(fire, function(a_1, ...)
    if DETECTION_SIGNALS[a_1] then
        DETECTION_SIGNALS[a_1]{...};
        return;
    end

    remote:FireServer(encode(a_1), ...);
end);

return true;
