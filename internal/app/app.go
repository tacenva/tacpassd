package app

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-core/config"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	tacpassapp "github.com/tacenva/tacpass-core/app"
	"github.com/tacenva/tacpassd/internal/feature/accesscontrol"
	"github.com/tacenva/tacpassd/internal/feature/auth"
	"github.com/tacenva/tacpassd/internal/feature/vault"
	"github.com/tacenva/tacpassd/internal/mdns"
	"github.com/tacenva/tacpassd/internal/middleware"
	"github.com/tacenva/tacpassd/internal/server"
	"github.com/tacenva/tacpassd/internal/tls"
	"github.com/tacenva/tacpassd/internal/vpn"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Run(dev bool) error {
	initAdmin := flag.String(
		"init-admin",
		"",
		"init admin",
	)

	userStatus := flag.Bool(
		"user-status",
		false,
		"change a user's status interactively (approve/revoke)",
	)

	version := flag.Bool(
		"version",
		false,
		"show application version",
	)

	flag.Parse()

	if *version {
		fmt.Println(Version)
		return nil
	}

	cfg, err := config.LoadOrCreate(dev)
	if err != nil {
		return err
	}

	sqliteDB, err := OpenSQLite(
		cfg.Path(config.AppDBFileName),
	)
	if err != nil {
		return err
	}

	if err := tacpassapp.Migrate(sqliteDB); err != nil {
		return err
	}

	tacenvaDB := database.New(
		cfg.VaultDir(),
	)

	services := tacpassapp.NewServices(
		sqliteDB,
		tacenvaDB,
	)

	if *initAdmin != "" {
		return initAdminPrivilege(
			services,
			*initAdmin,
			cfg.SotID,
		)
	}

	if *userStatus {
		return changeUserStatusInteractive(
			services,
			cfg.SotID,
		)
	}

	return serve(
		cfg,
		services,
	)
}

func serve(
	cfg *config.Config,
	services *tacpassapp.Services,
) error {
	authHandler := auth.NewHandler(
		services.Auth,
		cfg,
	)

	accesscontrolHandler := accesscontrol.NewHandler(
		services.AccessControl,
		cfg,
	)

	vaultHandler := vault.NewHandler(
		services.Vault,
		cfg,
	)

	authMiddleware := middleware.NewAuth(
		services.Auth,
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

	// LAN discovery.
	mdnsServer, err := mdns.Start(
		cfg.Server.Hostname,
		cfg.Server.Port,
	)
	if err != nil {
		return fmt.Errorf(
			"start mdns: %w",
			err,
		)
	}

	defer mdnsServer.Shutdown()

	fmt.Printf(
		"mDNS service started: %s.local:%d\n",
		cfg.Server.Hostname,
		cfg.Server.Port,
	)

	// VPN discovery.
	vpnServer, err := vpn.Start(
		"tun0",
		cfg.Server.Hostname,
		cfg.Server.Port,
	)
	if err != nil {
		fmt.Printf(
			"VPN discovery disabled: %v\n",
			err,
		)
	} else {
		defer vpnServer.Shutdown()

		fmt.Printf(
			"VPN discovery service started: tun0:%d\n",
			vpn.DiscoveryPort,
		)
	}

	return httpServer.Run(
		cfg.Path(cfg.TLS.CertFile),
		cfg.Path(cfg.TLS.KeyFile),
	)
}

func ensureTLS(
	cfg *config.Config,
) error {
	if err := tls.GenerateSelfSignedCert(
		cfg.Path(cfg.TLS.CertFile),
		cfg.Path(cfg.TLS.KeyFile),
		cfg.Server.Hostname,
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
		sqlite.Open(path+"?_foreign_keys=on"),
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

func initAdminPrivilege(
	services *tacpassapp.Services,
	name string,
	sotID string,
) error {
	keyPair, _, err := services.AccessControl.Internal.InitAccess(
		sotID,
	)
	if err != nil {
		return err
	}

	fmt.Println(
		"admin keypair created:",
		keyPair.PublicKey,
		keyPair.PrivateKey,
	)

	return nil
}

func changeUserStatusInteractive(
	services *tacpassapp.Services,
	sotID string,
) error {
	accessUnitList, err := services.AccessControl.Internal.AccessUnitList(
		sotID,
	)
	if err != nil {
		return err
	}

	if len(accessUnitList) == 0 {
		fmt.Println("no access unit found")
		return nil
	}

	fmt.Println("access units:")

	for i, accessUnit := range accessUnitList {
		fmt.Printf(
			"[%d] %s (%s)\n",
			i+1,
			accessUnit.Name,
			accessUnit.Level,
		)
	}

	accessUnitIndex, err := readSelection(
		"select access unit: ",
		len(accessUnitList),
	)
	if err != nil {
		return err
	}

	selectedUnit := accessUnitList[accessUnitIndex]

	userList, err := services.AccessControl.Internal.UserList(
		sotID,
		selectedUnit.ID,
	)
	if err != nil {
		return err
	}

	if len(userList) == 0 {
		fmt.Printf(
			"no users found for access unit %q\n",
			selectedUnit.Name,
		)
		return nil
	}

	fmt.Printf(
		"\nusers for access unit %q:\n",
		selectedUnit.Name,
	)

	for i, user := range userList {
		fmt.Printf(
			"[%d] %s (%s) status=%s\n",
			i+1,
			user.Hostname,
			user.ID,
			user.Status,
		)
	}

	userIndex, err := readSelection(
		"select user: ",
		len(userList),
	)
	if err != nil {
		return err
	}

	selectedUser := userList[userIndex]

	fmt.Println("\nselect action:")
	fmt.Println("[1] Approve")
	fmt.Println("[2] Revoke")

	actionIndex, err := readSelection(
		"select action: ",
		2,
	)
	if err != nil {
		return err
	}

	var (
		status  tacenvaentity.UserStatus
		message string
	)

	switch actionIndex {
	case 0:
		status = tacenvaentity.UserStatusApproved
		message = "approved"
	case 1:
		status = tacenvaentity.UserStatusRevoked
		message = "revoked"
	}

	if err := services.AccessControl.Internal.SetUserStatus(
		selectedUser.ID,
		status,
	); err != nil {
		return err
	}

	fmt.Printf(
		"\nuser %s: id=%s hostname=%s\n",
		message,
		selectedUser.ID,
		selectedUser.Hostname,
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
