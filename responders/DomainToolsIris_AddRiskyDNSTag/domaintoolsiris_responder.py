#!/usr/bin/env python3
# encoding: utf-8


from cortexutils.responder import Responder


class DomainToolsIris(Responder):
    def __init__(self):
        Responder.__init__(self)

    def run(self):
        Responder.run(self)
        if self.get_param("data.dataType") == "domain":
            self.report({"data": self.get_data()})
        else:
            self.report({"data": 'Can only operate on "domain" observables'})

    def operations(self, raw):
        build_list = []
        taxonomies = (
            raw.get("data", {})
            .get("reports", {})
            .get("DomainToolsIris_Investigate_1_0", {})
            .get("taxonomies", None)
        )

        for x in taxonomies:
            if x["predicate"] == "Risk Score":
                if int(x["value"]) > int(self.get_param("config.high_risk_threshold")):
                    build_list.append(
                        self.build_operation("AddTagToCase", tag="DT:Risky DNS")
                    )
                    build_list.append(
                        self.build_operation("AddTagToArtifact", tag="DT:Risky DNS")
                    )
        return build_list


if __name__ == "__main__":
    DomainToolsIris().run()
