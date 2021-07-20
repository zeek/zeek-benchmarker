# This is a simple plugin for zeekctl that sets the BROKER_METRICS_PORT
# for each of the workers in a load-balanced setup.
import ZeekControl.plugin as PluginBase

class BrokerMetricsPort(PluginBase.Plugin):
    def __init__(self):
        super(BrokerMetricsPort, self).__init__(apiversion=1)

    def name(self):
        return "brokermetricsport"

    def nodeKeys(self):
        return ["enable", "all_workers"]

    def pluginVersion(self):
        return 1

    def options(self):
        return [("base_worker_port", "int", 4050, "Base port for the workers to use")]

    def init(self):
        port = self.getOption("base_worker_port")

        # we could use enumerate here but we only want to increase the port
        # number when we find a worker, not on every node
        for nn in self.nodes():
            if nn.type == "worker":
                port = port + 1
                print("Set BROKER_PORT to %d for worker" % port)
                nn.env_vars.setdefault("BROKER_METRICS_PORT", port)

        return True
