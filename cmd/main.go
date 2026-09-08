package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/tacenva/database"
	tacpass_core "github.com/tacenva/tacpass-core"
	accesscontrolCore "github.com/tacenva/tacpass-core/accesscontrol"
	authCore "github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/permission"
	"github.com/tacenva/tacpass-core/user"
	vaultCore "github.com/tacenva/tacpass-core/vault"
	"github.com/tacenva/tacpass-core/vaultaccess"
	"github.com/tacenva/tacpassd/internal/config"
	"github.com/tacenva/tacpassd/internal/feature/accesscontrol"
	"github.com/tacenva/tacpassd/internal/feature/auth"
	"github.com/tacenva/tacpassd/internal/feature/vault"
	"github.com/tacenva/tacpassd/internal/middleware"
	"github.com/tacenva/tacpassd/internal/server"
	"github.com/tacenva/tacpassd/internal/tls"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	addAdmin := flag.String(
		"add-admin",
		"",
		"add permission with admin privilege",
	)

	approve := flag.Bool(
		"approve",
		false,
		"approve a user interactively",
	)

	flag.Parse()

	cfg, err := config.LoadOrCreate()
	if err != nil {
		log.Fatal(err)
	}

	sqliteDB, err := OpenSQLite(
		cfg.Path(config.AppDBFileName),
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := tacpass_core.Migrate(sqliteDB); err != nil {
		log.Fatal(err)
	}

	accesscontrolService,
		authService := getCoreServices(
		sqliteDB,
	)

	if *addAdmin != "" {
		if err := addAdminPrivilege(
			accesscontrolService,
			*addAdmin,
		); err != nil {
			log.Fatal(err)
		}

		return
	}

	if *approve {
		if err := approveUserInteractive(
			accesscontrolService,
		); err != nil {
			log.Fatal(err)
		}

		return
	}

	if err := serve(
		cfg,
		sqliteDB,
		accesscontrolService,
		authService,
	); err != nil {
		log.Fatal(err)
	}
}

func serve(
	cfg *config.Config,
	sqliteDB *gorm.DB,
	accesscontrolService *accesscontrolCore.Service,
	authService *authCore.Service,
) error {
	tacenvaDB := database.New(
		cfg.VaultDir(),
	)

	vaultRepository := vaultCore.NewRepository(
		sqliteDB,
	)

	vaultaccessRepository := vaultaccess.NewRepository(
		sqliteDB,
	)

	vaultaccessService := vaultaccess.NewService(
		vaultaccessRepository,
	)

	vaultService := vaultCore.NewService(
		vaultRepository,
		tacenvaDB,
		vaultaccessService,
	)

	authHandler := auth.NewHandler(
		authService,
	)

	accesscontrolHandler := accesscontrol.NewHandler(
		accesscontrolService,
	)

	vaultHandler := vault.NewHandler(
		vaultService,
		tacenvaDB,
		vaultaccessService,
	)

	authMiddleware := middleware.NewAuth(
		authService,
	)

	router := server.NewRouter(
		authMiddleware,
		authHandler,
		accesscontrolHandler,
		vaultHandler,
	)

	var handler http.Handler = router

	handler = middleware.Debug(handler)

	if err := ensureTLS(cfg); err != nil {
		return err
	}

	httpServer := server.New(
		fmt.Sprintf(
			"0.0.0.0:%d",
			cfg.Server.Port,
		),
		handler,
	)

	return httpServer.Run(
		cfg.Path(cfg.TLS.CertFile),
		cfg.Path(cfg.TLS.KeyFile),
	)
}

func ensureTLS(cfg *config.Config) error {
	if err := tls.GenerateSelfSignedCert(
		cfg.Path(cfg.TLS.CertFile),
		cfg.Path(cfg.TLS.KeyFile),
	); err != nil {
		return fmt.Errorf(
			"generate tls certificate: %w",
			err,
		)
	}

	return nil
}

func OpenSQLite(
	path string,
) (*gorm.DB, error) {
	db, err := gorm.Open(
		sqlite.Open(path),
		&gorm.Config{},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"open sqlite database: %w",
			err,
		)
	}

	return db, nil
}

func getCoreServices(
	sqliteDB *gorm.DB,
) (
	*accesscontrolCore.Service,
	*authCore.Service,
) {
	userRepository := user.NewRepository(
		sqliteDB,
	)

	userService := user.NewService(
		userRepository,
	)

	permissionRepository := permission.NewRepository(
		sqliteDB,
	)

	permissionService := permission.NewService(
		permissionRepository,
	)

	accesscontrolService := accesscontrolCore.NewService(
		userService,
		permissionService,
	)

	authService := authCore.NewService(
		userService,
		permissionService,
	)

	return accesscontrolService, authService
}

func addAdminPrivilege(
	accesscontrolService *accesscontrolCore.Service,
	name string,
) error {
	_, keypair, err := accesscontrolService.Create(
		name,
		entity.PrivilegeAdmin,
	)
	if err != nil {
		return err
	}

	fmt.Println(
		"admin keypair created:",
		keypair.PublicKey,
		keypair.PrivateKey,
	)

	return nil
}

func approveUserInteractive(
	accesscontrolService *accesscontrolCore.Service,
) error {
	permissions, err := accesscontrolService.List()
	if err != nil {
		return err
	}

	if len(permissions) == 0 {
		fmt.Println("no permission found")
		return nil
	}

	fmt.Println("permissions:")

	for i, permission := range permissions {
		fmt.Printf(
			"[%d] %s (%s)\n",
			i+1,
			permission.Name,
			permission.Privilege,
		)
	}

	permissionIndex, err := readSelection(
		"select permission: ",
		len(permissions),
	)
	if err != nil {
		return err
	}

	selectedPermission := permissions[permissionIndex]

	users, err := accesscontrolService.UserList(
		selectedPermission.ID,
	)
	if err != nil {
		return err
	}

	if len(users) == 0 {
		fmt.Printf(
			"no users found for permission %q\n",
			selectedPermission.Name,
		)

		return nil
	}

	fmt.Printf(
		"\nusers for permission %q:\n",
		selectedPermission.Name,
	)

	for i, user := range users {
		fmt.Printf(
			"[%d] %s (%s) status=%s\n",
			i+1,
			user.Hostname,
			user.ID,
			user.Status,
		)
	}

	userIndex, err := readSelection(
		"select user to approve: ",
		len(users),
	)
	if err != nil {
		return err
	}

	selectedUser := users[userIndex]

	approvedUser, err := accesscontrolService.ApproveUser(
		selectedUser.ID,
	)
	if err != nil {
		return err
	}

	fmt.Printf(
		"\nuser approved: id=%s hostname=%s\n",
		approvedUser.ID,
		approvedUser.Hostname,
	)

	return nil
}

func readSelection(
	prompt string,
	max int,
) (int, error) {
	for {
		fmt.Print(prompt)

		var input int

		if _, err := fmt.Scanln(&input); err != nil {
			return 0, fmt.Errorf(
				"read selection: %w",
				err,
			)
		}

		if input < 1 || input > max {
			fmt.Printf(
				"invalid selection, choose 1-%d\n",
				max,
			)

			continue
		}

		return input - 1, nil
	}
}
