myApp
    .controller('loginCtrl',['$scope', function ($scope)
{
    $scope.postData = function ()
    {
        console.log($scope.userlogin);
    }
}]);