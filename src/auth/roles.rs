#[derive(Debug, Clone, PartialEq)]
pub enum Role {
    Admin,
    Operator,
    Viewer,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum Permission {
    ViewStats,
    ViewRules,
    ManageRules,
    ReloadConfig,
    ManageUsers,
}

impl Role {
    pub fn from_str(s: &str) -> Self {
        match s {
            "admin" => Role::Admin,
            "operator" => Role::Operator,
            _ => Role::Viewer,
        }
    }

    pub fn has_permission(&self, perm: Permission) -> bool {
        match (self, perm) {
            (_, Permission::ViewStats) => true,
            (_, Permission::ViewRules) => true,
            (Role::Admin, _) => true,
            (Role::Operator, Permission::ManageRules) => true,
            (Role::Operator, Permission::ReloadConfig) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_has_all_permissions() {
        let admin = Role::Admin;
        assert!(admin.has_permission(Permission::ViewStats));
        assert!(admin.has_permission(Permission::ViewRules));
        assert!(admin.has_permission(Permission::ManageRules));
        assert!(admin.has_permission(Permission::ReloadConfig));
        assert!(admin.has_permission(Permission::ManageUsers));
    }

    #[test]
    fn operator_cannot_manage_users() {
        let op = Role::Operator;
        assert!(op.has_permission(Permission::ViewStats));
        assert!(op.has_permission(Permission::ViewRules));
        assert!(op.has_permission(Permission::ManageRules));
        assert!(op.has_permission(Permission::ReloadConfig));
        assert!(!op.has_permission(Permission::ManageUsers));
    }

    #[test]
    fn viewer_can_only_view() {
        let viewer = Role::Viewer;
        assert!(viewer.has_permission(Permission::ViewStats));
        assert!(viewer.has_permission(Permission::ViewRules));
        assert!(!viewer.has_permission(Permission::ManageRules));
        assert!(!viewer.has_permission(Permission::ReloadConfig));
        assert!(!viewer.has_permission(Permission::ManageUsers));
    }

    #[test]
    fn from_str_parses_roles() {
        assert_eq!(Role::from_str("admin"), Role::Admin);
        assert_eq!(Role::from_str("operator"), Role::Operator);
        assert_eq!(Role::from_str("viewer"), Role::Viewer);
        assert_eq!(Role::from_str("unknown"), Role::Viewer);
    }
}
