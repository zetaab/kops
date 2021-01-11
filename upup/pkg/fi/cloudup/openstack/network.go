/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package openstack

import (
	"fmt"

	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/attributestags"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/external"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/pagination"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kops/util/pkg/vfs"
)

func (c *openstackCloud) AppendTag(resource string, id string, tag string) error {
	return appendTag(c, resource, id, tag)
}

func appendTag(c OpenstackCloud, resource string, id string, tag string) error {
	done, err := vfs.RetryWithBackoff(readBackoff, func() (bool, error) {
		err := attributestags.Add(c.NetworkingClient(), resource, id, tag).ExtractErr()
		if err != nil {
			return false, fmt.Errorf("error appending tag %s: %v", tag, err)
		}
		return true, nil
	})
	if err != nil {
		return err
	} else if done {
		return nil
	} else {
		return wait.ErrWaitTimeout
	}
}

func (c *openstackCloud) DeleteTag(resource string, id string, tag string) error {
	return deleteTag(c, resource, id, tag)
}

func deleteTag(c OpenstackCloud, resource string, id string, tag string) error {
	done, err := vfs.RetryWithBackoff(readBackoff, func() (bool, error) {
		err := attributestags.Delete(c.NetworkingClient(), resource, id, tag).ExtractErr()
		if err != nil {
			return false, fmt.Errorf("error deleting tag %s: %v", tag, err)
		}
		return true, nil
	})
	if err != nil {
		return err
	} else if done {
		return nil
	} else {
		return wait.ErrWaitTimeout
	}
}

func (c *openstackCloud) ReplaceAllTags(resource string, id string, opts attributestags.ReplaceAllOptsBuilder) error {
	return replaceAllTags(c, resource, id, opts)
}

func replaceAllTags(c OpenstackCloud, resource string, id string, opts attributestags.ReplaceAllOptsBuilder) error {
	done, err := vfs.RetryWithBackoff(readBackoff, func() (bool, error) {
		_, err := attributestags.ReplaceAll(c.NetworkingClient(), resource, id, opts).Extract()
		if err != nil {
			return false, fmt.Errorf("error replacing tags %v: %v", opts, err)
		}
		return true, nil
	})
	if err != nil {
		return err
	} else if done {
		return nil
	} else {
		return wait.ErrWaitTimeout
	}
}

func (c *openstackCloud) FindNetworkBySubnetID(subnetID string) (*networks.Network, error) {
	return findNetworkBySubnetID(c, subnetID)
}

func findNetworkBySubnetID(c OpenstackCloud, subnetID string) (*networks.Network, error) {
	var rslt *networks.Network
	done, err := vfs.RetryWithBackoff(readBackoff, func() (bool, error) {
		subnet, err := c.GetSubnet(subnetID)
		if err != nil {
			return false, fmt.Errorf("error retrieving subnet with id %s: %v", subnetID, err)
		}

		netID := subnet.NetworkID
		net, err := c.GetNetwork(netID)
		if err != nil {
			return false, fmt.Errorf("error retrieving network with id %s: %v", netID, err)
		}
		rslt = net
		return true, nil
	})
	if err != nil {
		return nil, err
	} else if done {
		return rslt, nil
	} else {
		return nil, wait.ErrWaitTimeout
	}
}

func (c *openstackCloud) GetNetwork(id string) (*networks.Network, error) {
	return getNetwork(c, id)
}

func getNetwork(c OpenstackCloud, id string) (*networks.Network, error) {
	var network *networks.Network
	done, err := vfs.RetryWithBackoff(readBackoff, func() (bool, error) {
		r, err := networks.Get(c.NetworkingClient(), id).Extract()
		if err != nil {
			return false, fmt.Errorf("error retrieving network with id %s: %v", id, err)
		}
		network = r
		return true, nil
	})
	if err != nil {
		return network, err
	} else if done {
		return network, nil
	} else {
		return network, wait.ErrWaitTimeout
	}
}

func (c *openstackCloud) ListNetworks(opt networks.ListOptsBuilder) ([]networks.Network, error) {
	return listNetworks(c, opt)
}

func listNetworks(c OpenstackCloud, opt networks.ListOptsBuilder) ([]networks.Network, error) {
	var ns []networks.Network

	done, err := vfs.RetryWithBackoff(readBackoff, func() (bool, error) {
		allPages, err := networks.List(c.NetworkingClient(), opt).AllPages()
		if err != nil {
			return false, fmt.Errorf("error listing networks: %v", err)
		}

		r, err := networks.ExtractNetworks(allPages)
		if err != nil {
			return false, fmt.Errorf("error extracting networks from pages: %v", err)
		}
		ns = r
		return true, nil
	})
	if err != nil {
		return ns, err
	} else if done {
		return ns, nil
	} else {
		return ns, wait.ErrWaitTimeout
	}
}

func (c *openstackCloud) GetExternalNetwork() (net *networks.Network, err error) {
	return getExternalNetwork(c, *c.extNetworkName)
}

func getExternalNetwork(c OpenstackCloud, networkName string) (net *networks.Network, err error) {
	type NetworkWithExternalExt struct {
		networks.Network
		external.NetworkExternalExt
	}

	done, err := vfs.RetryWithBackoff(readBackoff, func() (bool, error) {

		err = networks.List(c.NetworkingClient(), networks.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
			var externalNetwork []NetworkWithExternalExt
			err := networks.ExtractNetworksInto(page, &externalNetwork)
			if err != nil {
				return false, err
			}
			for _, externalNet := range externalNetwork {
				if externalNet.External && externalNet.Name == networkName {
					net = &externalNet.Network
					return true, nil
				}
			}
			return true, nil
		})
		if err != nil {
			return false, nil
		}
		return net != nil, nil
	})

	if err != nil {
		return net, err
	} else if done {
		return net, nil
	} else {
		return net, wait.ErrWaitTimeout
	}
}

func (c *openstackCloud) CreateNetwork(opt networks.CreateOptsBuilder) (*networks.Network, error) {
	return createNetwork(c, opt)
}

func createNetwork(c OpenstackCloud, opt networks.CreateOptsBuilder) (*networks.Network, error) {
	var n *networks.Network

	done, err := vfs.RetryWithBackoff(writeBackoff, func() (bool, error) {
		r, err := networks.Create(c.NetworkingClient(), opt).Extract()
		if err != nil {
			return false, fmt.Errorf("error creating network: %v", err)
		}
		n = r
		return true, nil
	})
	if err != nil {
		return n, err
	} else if done {
		return n, nil
	} else {
		return n, wait.ErrWaitTimeout
	}
}

func (c *openstackCloud) DeleteNetwork(networkID string) error {
	return deleteNetwork(c, networkID)
}

func deleteNetwork(c OpenstackCloud, networkID string) error {
	done, err := vfs.RetryWithBackoff(writeBackoff, func() (bool, error) {
		err := networks.Delete(c.NetworkingClient(), networkID).ExtractErr()
		if err != nil && !isNotFound(err) {
			return false, fmt.Errorf("error deleting network: %v", err)
		}
		return true, nil
	})
	if err != nil {
		return err
	} else if done {
		return nil
	} else {
		return wait.ErrWaitTimeout
	}
}
