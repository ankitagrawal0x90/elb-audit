import boto3

# pylint: disable=invalid-name,missing-docstring

class ELBAudit(object):

    def __init__(self):
        self.client = boto3.client('elbv2')
        # self.elbs = self.client.describe_load_balancers()
        self.elbs = self._get_elbs()
        self.elb_list = list()
        self.preferred_ssl_policy = 'ELBSecurityPolicy-TLS-1-2-2017-01'
        self.listener_list = list()


    def _get_elbs(self):
        """
            assemble list of elbs from multiple paginated queries
        """
        elb_list = []
        pag = self.client.get_paginator('describe_load_balancers')

        for p in pag.paginate():
            elb_list.extend(p['LoadBalancers'])
            print "\telb_list", len(elb_list)

        return {'LoadBalancers': elb_list}

    def _get_listeners(self, **kwargs):
        """
            assemble list of listeners from multiple paginated queries
        """
        listener_list = []
        pag = self.client.get_paginator('describe_listeners')

        for p in pag.paginate(**kwargs):
            listener_list.extend(p['Listeners'])

        return {'Listeners': listener_list}

    def _get_target_groups(self, **kwargs):
        """
            assemble list of target_groups from multiple paginated queries
        """
        target_list = []
        pag = self.client.get_paginator('describe_target_groups')

        for p in pag.paginate(**kwargs):
            target_list.extend(p['TargetGroups'])

        return {'TargetGroups': target_list}


    def get_elbs_by_no_listeners(self):
        print "ELB ARNs with no listeners"
        print "--------------------------"
        for elb in self.elbs['LoadBalancers']:
            elb_arn = elb['LoadBalancerArn']
            # listeners = self.client.describe_listeners(LoadBalancerArn=elb_arn)
            listeners = self._get_listeners(LoadBalancerArn=elb_arn)
            if not listeners['Listeners']:
                self.elb_list.append(elb_arn)
                print elb_arn

    def get_elb_service_tag(self, elb_list=None):
        print "ELB ARNs and Service Owners"
        print "--------------------------"
        if elb_list is None:
            elb_list = self.elb_list
        elb_list_len = len(elb_list)
        counter = 0
        # describe_tags takes only 20 ARNs at a time
        while counter < elb_list_len:
            if elb_list_len - counter >= 20:
                response = self.client.describe_tags(ResourceArns=elb_list[counter:counter+20])
                counter += 20
            else:
                response = self.client.describe_tags(ResourceArns=elb_list[counter:elb_list_len])
                counter = elb_list_len
                for tagdescription in response['TagDescriptions']:
                    elb_arn = tagdescription['ResourceArn']
                    for tag in tagdescription['Tags']:
                        if tag['Key'] == 'service':
                            print "%s\t %s" % (elb_arn, tag['Value'])


    def get_listeners_by_old_ssl_policy(self):
        print "Ports and Listener ARNs with old SSL policies"
        print "---------------------------------------------"
        for elb in self.elbs['LoadBalancers']:
            elb_arn = elb['LoadBalancerArn']
            # listeners = self.client.describe_listeners(LoadBalancerArn=elb_arn)
            listeners = self._get_listeners(LoadBalancerArn=elb_arn)
            listener_dict = dict()
            for listener in listeners['Listeners']:
                if 'SslPolicy' in listener and listener['SslPolicy'] != self.preferred_ssl_policy:
                    listener_dict[listener['ListenerArn']] = listener['Port']
                    self.listener_list.append(listener['ListenerArn'])
            if listener_dict:
                print elb_arn
                for k, v in listener_dict.iteritems():
                    print "\t%s\t%s" % (v, k)


    def set_listeners_ssl_policy(self, listener_list=None):
        print "Updating listeners"
        print "------------------"
        if listener_list is None:
            listener_list = self.listener_list
        for listener_arn in listener_list:
            self.client.modify_listener(
                ListenerArn=listener_arn,
                SslPolicy=self.preferred_ssl_policy)
            print listener_arn


    def delete_elbs(self, disable_delete_protection=False, elb_list=None):
        if elb_list is None:
            elb_list = self.elb_list
        for elb_arn in elb_list:
            attributes = self.client.describe_load_balancer_attributes(LoadBalancerArn=elb_arn)
            for attribute in attributes['Attributes']:
                if attribute['Key'] == 'deletion_protection.enabled' and \
                   attribute['Value'] == 'true':
                    if disable_delete_protection:
                        response = self.client.modify_load_balancer_attributes(
                            LoadBalancerArn=elb_arn,
                            Attributes=[
                                {
                                    'Key': 'deletion_protection.enabled',
                                    'Value': 'false'
                                },
                            ]
                        )
                        print response
                        response = self.client.delete_load_balancer(LoadBalancerArn=elb_arn)
                        print response
                    else:
                        print "Cannot delete %s - data protection enabled"
                    break
                elif attribute['Key'] == 'deletion_protection.enabled' and \
                   attribute['Value'] == 'false':
                    response = self.client.delete_load_balancer(LoadBalancerArn=elb_arn)
                    print response
                    break


    def get_elbs_by_no_target(self):
        print "ELB ARNs with no targets"
        print "------------------------"
        for elb in self.elbs['LoadBalancers']:
            elb_arn = elb['LoadBalancerArn']
            # target_groups = self.client.describe_target_groups(LoadBalancerArn=elb_arn)
            target_groups = self._get_target_groups(LoadBalancerArn=elb_arn)
            targets_num = 0
            for target_group in target_groups['TargetGroups']:
                target_group_arn = target_group['TargetGroupArn']
                targets = self.client.describe_target_health(TargetGroupArn=target_group_arn)
                targets_num += len(targets['TargetHealthDescriptions'])
            if not targets_num:
                self.elb_list.append(elb_arn)
                print elb_arn


if __name__ == '__main__':
    elbAudit = ELBAudit()
    #elbAudit.get_elbs_by_no_target()
    #elbAudit.get_elb_service_tag()
    elbAudit.get_listeners_by_old_ssl_policy()
    elbAudit.set_listeners_ssl_policy()
    #elbAudit.get_elbs_by_no_listeners()
    #elbAudit.delete_elbs()
    #elbAudit.delete_elbs(True)
    #elbAudit.delete_elbs(True, ["arn:aws:elasticloadbalancing:us-east-1:999999999999:loadbalancer/app/alb-test-io/9a9a9a9a9a9a9a"])
