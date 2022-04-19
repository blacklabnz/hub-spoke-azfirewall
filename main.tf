locals {
  org         = "blk"
  rg          = "${local.org}-hub-spoke"
  rg_location = "australiaeast"

  vnets = {
    vnet_hub    = { name = "${local.org}-hub", address_space = "10.0.0.0/16" }
    vnet_a      = { name = "${local.org}-spoke-a", address_space = "10.1.0.0/16" }
    vnet_b      = { name = "${local.org}-spoke-b", address_space = "10.2.0.0/16" }
    vnet_onprem = { name = "${local.org}-spoke-onprem", address_space = "192.168.1.0/24" }
  }

  subnets = {
    hub_gw            = { vnet = "${local.org}-hub", name = "GatewaySubnet", address_prefixes = "10.0.1.0/24" }
    hub_firewall      = { vnet = "${local.org}-hub", name = "AzureFirewallSubnet", address_prefixes = "10.0.2.0/24" }
    hub_firewall_mgmt = { vnet = "${local.org}-hub", name = "AzureFirewallManagementSubnet", address_prefixes = "10.0.3.0/24" }
    hub_jumphost      = { vnet = "${local.org}-hub", name = "jump", address_prefixes = "10.0.4.0/24" }
    a_app             = { vnet = "${local.org}-spoke-a", name = "app", address_prefixes = "10.1.1.0/24" }
    b_app             = { vnet = "${local.org}-spoke-b", name = "app", address_prefixes = "10.2.1.0/24" }
    onprem_gw         = { vnet = "${local.org}-spoke-onprem", name = "GatewaySubnet", address_prefixes = "192.168.1.0/26" }
    onprem_app        = { vnet = "${local.org}-spoke-onprem", name = "app", address_prefixes = "192.168.1.64/26" }
  }

  peering = {
    hub_to_spoke_a = { name = "${local.vnets.vnet_hub.name}-to-${local.vnets.vnet_a.name}", vnet = "vnet_hub", remote = "vnet_a", use_remote_gw = false }
    spoke_a_to_hub = { name = "${local.vnets.vnet_a.name}-to-${local.vnets.vnet_hub.name}", vnet = "vnet_a", remote = "vnet_hub", use_remote_gw = true }
    hub_to_spoke_b = { name = "${local.vnets.vnet_hub.name}-to-${local.vnets.vnet_b.name}", vnet = "vnet_hub", remote = "vnet_b", use_remote_gw = false }
    spoke_b_to_hub = { name = "${local.vnets.vnet_b.name}-to-${local.vnets.vnet_hub.name}", vnet = "vnet_b", remote = "vnet_hub", use_remote_gw = true }
  }

  fw_name   = "${local.org}-azfw"
  fw_policy = "${local.org}-fw-policy"

  fw_ip = {
    fw_ip      = { name = "${local.org}-fw-ip" }
    fw_mgmt_ip = { name = "${local.org}-fw-mgmt-ip" }
  }

  fw_rules_group_allow = "${local.org}-fw-rules-group-allow"
  fw_rules_group_deny  = "${local.org}-fw-rules-group-deny"

  udr_peers = "${local.org}-udr-peers"
  udr_hub   = "${local.org}-udr-hub"

  gw = {
    hub_gw    = { name = "${local.org}-hub-gw", ip = "${local.org}-hub-gw-ip", vpn_name = "${local.org}-onprem-hub", peer = "onprem_gw" }
    onprem_gw = { name = "${local.org}-onprem-gw", ip = "${local.org}-onprem-gw-ip", vpn_name = "${local.org}-hub-onprem", peer = "hub_gw" }
  }
}

resource "azurerm_resource_group" "hub_spoke" {
  name     = local.rg
  location = local.rg_location
}

resource "azurerm_virtual_network" "hub_spoke" {
  for_each            = local.vnets
  name                = each.value["name"]
  location            = local.rg_location
  resource_group_name = azurerm_resource_group.hub_spoke.name
  address_space       = [each.value["address_space"]]
  depends_on          = [azurerm_resource_group.hub_spoke]
}

resource "azurerm_subnet" "hub-spoke" {
  for_each                                       = local.subnets
  name                                           = each.value["name"]
  resource_group_name                            = local.rg
  virtual_network_name                           = each.value["vnet"]
  address_prefixes                               = [each.value["address_prefixes"]]
  enforce_private_link_endpoint_network_policies = true

  depends_on = [azurerm_virtual_network.hub_spoke]
}

resource "azurerm_virtual_network_peering" "hub_to_spoke_a" {
  for_each                     = local.peering
  name                         = each.value["name"]
  resource_group_name          = local.rg
  virtual_network_name         = azurerm_virtual_network.hub_spoke[each.value["vnet"]].name
  remote_virtual_network_id    = azurerm_virtual_network.hub_spoke[each.value["remote"]].id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = true
  use_remote_gateways          = each.value["use_remote_gw"]
}

resource "azurerm_firewall_policy" "fw_policy" {
  name                = local.fw_policy
  resource_group_name = azurerm_resource_group.hub_spoke.name
  location            = local.rg_location
}

resource "azurerm_public_ip" "fw_ip" {
  for_each            = local.fw_ip
  name                = each.value["name"]
  location            = local.rg_location
  resource_group_name = azurerm_resource_group.hub_spoke.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# resource "azurerm_firewall" "fw" {
#   name                = local.fw_name
#   location            = local.rg_location
#   resource_group_name = azurerm_resource_group.hub_spoke.name
#   firewall_policy_id  = azurerm_firewall_policy.fw_policy.id

#   ip_configuration {
#     name                 = "ipconfig"
#     subnet_id            = azurerm_subnet.hub-spoke["hub_firewall"].id
#     public_ip_address_id = azurerm_public_ip.fw_ip["fw_ip"].id
#   }

#   management_ip_configuration {
#     name                 = "mgmt_ipconfig"
#     subnet_id            = azurerm_subnet.hub-spoke["hub_firewall_mgmt"].id
#     public_ip_address_id = azurerm_public_ip.fw_ip["fw_mgmt_ip"].id
#   }
# }

resource "azurerm_firewall_policy_rule_collection_group" "fw_rules_deny" {
  name               = local.fw_rules_group_deny
  firewall_policy_id = azurerm_firewall_policy.fw_policy.id
  priority           = 1000

  network_rule_collection {
    name     = "deny_netowrk_rule_coll"
    priority = 1000
    action   = "Deny"
    rule {
      name                  = "deny_all"
      protocols             = ["TCP", "UDP", "ICMP"]
      source_addresses      = ["*"]
      destination_addresses = ["*"]
      destination_ports     = ["*"]
    }
  }
}

resource "azurerm_firewall_policy_rule_collection_group" "fw_rules_allow" {
  name               = local.fw_rules_group_allow
  firewall_policy_id = azurerm_firewall_policy.fw_policy.id
  priority           = 500

  network_rule_collection {
    name     = "allow_network_rule_coll"
    priority = 500
    action   = "Allow"
    rule {
      name                  = "allow_blk"
      protocols             = ["TCP"]
      source_addresses      = [data.external.my_ip.result.ip]
      destination_addresses = ["*"]
      destination_ports     = ["*"]
    }

    rule {
      name                  = "allow_blk"
      protocols             = ["TCP"]
      source_addresses      = [data.external.my_ip.result.ip]
      destination_addresses = ["*"]
      destination_ports     = ["*"]
    }

    rule {
      name                  = "allow_hub_jumphost"
      protocols             = ["TCP"]
      source_addresses      = [local.subnets.hub_jumphost.address_prefixes]
      destination_addresses = ["*"]
      destination_ports     = ["*"]
    }

    rule {
      name                  = "allow_a_to_b"
      protocols             = ["TCP", "UDP", "ICMP"]
      source_addresses      = [local.subnets.a_app.address_prefixes]
      destination_addresses = [local.subnets.b_app.address_prefixes]
      destination_ports     = ["*"]
    }

    rule {
      name                  = "allow_b_to_a"
      protocols             = ["TCP", "UDP", "ICMP"]
      source_addresses      = [local.subnets.b_app.address_prefixes]
      destination_addresses = [local.subnets.a_app.address_prefixes]
      destination_ports     = ["*"]
    }

    rule {
      name                  = "allow_onprem_to_all"
      protocols             = ["TCP", "UDP", "ICMP"]
      source_addresses      = [local.subnets.onprem_app.address_prefixes]
      destination_addresses = ["*"]
      destination_ports     = ["*"]
    }
  }

  nat_rule_collection {
    name     = "nat_rule_coll"
    priority = 400
    action   = "Dnat"
    rule {
      name                = "jumphost_rdp"
      protocols           = ["TCP"]
      source_addresses    = [data.external.my_ip.result.ip]
      destination_address = "20.227.0.88"
      destination_ports   = ["3387"]
      translated_address  = "10.0.4.4"
      translated_port     = "3389"
    }

    rule {
      name                = "a_rdp"
      protocols           = ["TCP"]
      source_addresses    = [data.external.my_ip.result.ip]
      destination_address = "20.227.0.88"
      destination_ports   = ["3388"]
      translated_address  = "10.1.1.4"
      translated_port     = "3389"
    }

    rule {
      name                = "b_rdp"
      protocols           = ["TCP"]
      source_addresses    = [data.external.my_ip.result.ip]
      destination_address = "20.227.0.88"
      destination_ports   = ["3386"]
      translated_address  = "10.2.1.4"
      translated_port     = "3389"
    }
  }
}

resource "azurerm_route_table" "udr" {
  name                          = local.udr_peers
  location                      = local.rg_location
  resource_group_name           = azurerm_resource_group.hub_spoke.name
  disable_bgp_route_propagation = false

  route {
    name                   = "to_a_app_subnet"
    address_prefix         = local.subnets.a_app.address_prefixes
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "10.0.2.4"
  }

  route {
    name                   = "to_b_app_subnet"
    address_prefix         = local.subnets.b_app.address_prefixes
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "10.0.2.4"
  }
}

resource "azurerm_subnet_route_table_association" "udr_association_vnet_a" {
  route_table_id = azurerm_route_table.udr.id
  subnet_id      = azurerm_subnet.hub-spoke["a_app"].id
}

resource "azurerm_subnet_route_table_association" "udr_association_vnet_b" {
  route_table_id = azurerm_route_table.udr.id
  subnet_id      = azurerm_subnet.hub-spoke["b_app"].id
}

resource "azurerm_public_ip" "gw_ip" {
  for_each            = local.gw
  name                = each.value["ip"]
  location            = local.rg_location
  resource_group_name = azurerm_resource_group.hub_spoke.name
  allocation_method   = "Dynamic"
  sku                 = "Basic"
}

# resource "azurerm_virtual_network_gateway" "gw" {
#   for_each            = local.gw
#   name                = each.value["name"]
#   location            = local.rg_location
#   resource_group_name = azurerm_resource_group.hub_spoke.name

#   type     = "Vpn"
#   vpn_type = "RouteBased"

#   active_active = false
#   enable_bgp    = false
#   sku           = "VpnGw1"

#   ip_configuration {
#     name                          = "vnetGatewayConfig"
#     public_ip_address_id          = azurerm_public_ip.gw_ip[each.key].id
#     private_ip_address_allocation = "Dynamic"
#     subnet_id                     = azurerm_subnet.hub-spoke[each.key].id
#   }
# }

# resource "azurerm_virtual_network_gateway_connection" "hub_onprem" {
#   for_each            = local.gw
#   name                = each.value["vpn_name"]
#   location            = local.rg_location
#   resource_group_name = azurerm_resource_group.hub_spoke.name

#   type                            = "Vnet2Vnet"
#   virtual_network_gateway_id      = azurerm_virtual_network_gateway.gw[each.key].id
#   peer_virtual_network_gateway_id = azurerm_virtual_network_gateway.gw[each.value["peer"]].id

#   shared_key = "microsoft"
# }

resource "azurerm_route_table" "udr_hub" {
  name                          = local.udr_hub
  location                      = local.rg_location
  resource_group_name           = azurerm_resource_group.hub_spoke.name
  disable_bgp_route_propagation = true

  route {
    name                   = "to_a_app_subnet"
    address_prefix         = local.subnets.a_app.address_prefixes
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "10.0.2.4"
  }

  route {
    name                   = "to_b_app_subnet"
    address_prefix         = local.subnets.b_app.address_prefixes
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "10.0.2.4"
  }
}

resource "azurerm_subnet_route_table_association" "udr_association_vnet_hub" {
  route_table_id = azurerm_route_table.udr_hub.id
  subnet_id      = azurerm_subnet.hub-spoke["hub_gw"].id
}
