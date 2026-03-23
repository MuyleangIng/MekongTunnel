-- ============================================================
--  Reseed plan_configs with full PlanLimits JSON
-- ============================================================

INSERT INTO plan_configs (plan_id, config) VALUES
('free', '{
  "id": "free", "name": "Free", "price": null, "priceLabel": "Free",
  "maxTunnels": 2, "maxReservedSubdomains": 0, "maxCustomDomains": 0,
  "tunnelLifetimeHours": 24, "bandwidthGbPerMonth": 5,
  "requestLogDays": 0, "maxTeamMembers": 0,
  "requestInspection": false, "prioritySupport": false,
  "twoFaOptional": true, "color": "text-muted", "enabled": true
}'::jsonb),
('student', '{
  "id": "student", "name": "Student", "price": 0, "priceLabel": "Free",
  "maxTunnels": 3, "maxReservedSubdomains": 1, "maxCustomDomains": 0,
  "tunnelLifetimeHours": 168, "bandwidthGbPerMonth": 20,
  "requestLogDays": 7, "maxTeamMembers": 5,
  "requestInspection": true, "prioritySupport": false,
  "twoFaOptional": true, "color": "text-blue-400",
  "badge": "For Students", "enabled": true
}'::jsonb),
('pro', '{
  "id": "pro", "name": "Pro", "price": 10, "priceLabel": "$10/mo",
  "maxTunnels": 10, "maxReservedSubdomains": 3, "maxCustomDomains": 1,
  "tunnelLifetimeHours": -1, "bandwidthGbPerMonth": -1,
  "requestLogDays": 30, "maxTeamMembers": 5,
  "requestInspection": true, "prioritySupport": true,
  "twoFaOptional": true, "color": "text-gold",
  "badge": "Most Popular", "enabled": true
}'::jsonb),
('org', '{
  "id": "org", "name": "Organization", "price": 40, "priceLabel": "$40/mo",
  "maxTunnels": -1, "maxReservedSubdomains": -1, "maxCustomDomains": -1,
  "tunnelLifetimeHours": -1, "bandwidthGbPerMonth": -1,
  "requestLogDays": 90, "maxTeamMembers": -1,
  "requestInspection": true, "prioritySupport": true,
  "twoFaOptional": false, "color": "text-purple",
  "badge": "For Teams & Schools", "enabled": true
}'::jsonb)
ON CONFLICT (plan_id) DO UPDATE SET config = EXCLUDED.config;
